"""Feasibility and small algebra/full-protocol correctness runs, not paper timing."""
import argparse
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import sys
from time import perf_counter_ns
import uuid

from .backend import BackendUnavailable, select_backend
from .parameters import validate_current_parameters
from .telemetry import Timer, machine_info, peak_rss_bytes

PAPER_SHA256='481a41f1bb3c7dd0f971d6cee87151242910214fda3315887778b48dc9da9bd0'


def json_safe(value):
    if type(value) is int and value.bit_length()>256:
        return hex(value)
    if isinstance(value,dict):return {k:json_safe(v) for k,v in value.items()}
    if isinstance(value,(tuple,list)):return [json_safe(v) for v in value]
    return value


def dump(value):
    return json.dumps(json_safe(value),indent=2,ensure_ascii=False)+'\n'


def correctness(args):
    # Import late so preflight/parameter audits do not initialize arithmetic code.
    from .algebra import Ring
    from .fold import FoldParameters, initialize, round_prove, round_update, final_open, check_terminal
    if args.d not in (1,2) or not 1<=args.k<=4 or not 1<=args.cases<=32:
        raise ValueError('correctness runner is limited to d=1..2, k=1..4, cases=1..32')
    backend=select_backend(args.backend,allow_cpu_fallback=args.allow_cpu_fallback)
    q=(1<<31)-1 if args.d==1 else (1<<521)-1
    params=FoldParameters(args.d,4,args.k,q)
    audit=validate_current_parameters(d=args.d,T=4,k=args.k,q=q)
    ring=Ring(q,1<<args.d)
    rng=random.Random(args.seed)  # Reproducible TEST data; not cryptographic setup.
    rows=[]
    for case_index in range(args.cases):
        witness=tuple(tuple(rng.choice((-1,0,1)) for _ in range(ring.n)) for _ in range(ring.n))
        generators=tuple(tuple(ring.element(tuple(rng.randrange(q) for _ in range(ring.n))) for _ in range(args.k)) for _ in range(ring.n))
        challenges=tuple((rng.randrange(1,5),rng.randrange(1,5)) for _ in range(args.d))
        timer=Timer(); per_round=[]; records=[]
        with timer.stage('initialize'):
            state=initialize(params,witness,generators)
        public=state.public
        with timer.stage('prove_algebra'):
            for j,(x,y) in enumerate(challenges):
                started=perf_counter_ns(); result=round_prove(state,x,y)
                per_round.append({'round':j,'prove_ns':perf_counter_ns()-started})
                records.append(result.record);state=result.next_state
            opening=final_open(state)
        with timer.stage('public_replay'):
            for j,(record,(x,y)) in enumerate(zip(records,challenges)):
                started=perf_counter_ns(); public=round_update(public,record,x,y).next_state
                per_round[j]['replay_ns']=perf_counter_ns()-started
        with timer.stage('terminal_norm_and_opening'):
            accepted=check_terminal(public,opening)
        if not accepted:
            raise RuntimeError('honest mathematical test chain rejected')
        coefficient_count=1+sum(sum(len(poly.coefficients) for poly in module)
            for record in records for module in (record.L_vec,record.R_vec,record.L_poly,record.R_poly))
        rows.append({'case_index':case_index,'accepted':accepted,'stages_ns':timer.stages_ns,
                     'rounds':per_round,'proof_coefficient_count':coefficient_count})
    result={'schema_version':1,'run_id':str(uuid.uuid4()),'created_utc':datetime.now(timezone.utc).isoformat(),
            'data_kind':'correctness_test','complete_protocol':False,'formal_measurement':False,
            'profile':'explicit-challenge-algebra-v1','paper_sha256':PAPER_SHA256,
            'limitations':['No file codec or protocol wire','No Fiat-Shamir or certified epoch','No security claim; deterministic TEST setup','Timings are correctness telemetry, not A-group paper measurements'],
            'test_seed':args.seed,'d':args.d,'T':4,'k':args.k,'q':hex(q),'parameter_audit':asdict(audit),
            'backend':asdict(backend),'machine':machine_info(include_gpu=False),
            'file_bytes':None,'serialization_bytes':None,'peak_rss_bytes':peak_rss_bytes(),
            'peak_rss_scope':'whole process high-water mark, not isolated operation',
            'peak_vram_bytes':None,'cases':rows}
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'correctness.json').write_text(dump(result),encoding='utf-8')
    with (args.output/'correctness.csv').open('w',newline='',encoding='utf-8') as f:
        columns=['run_id','data_kind','profile','case_index','accepted','stage','elapsed_ns','requested_backend','actual_backend']
        writer=csv.DictWriter(f,fieldnames=columns);writer.writeheader()
        for row in rows:
            for stage,elapsed in row['stages_ns'].items():
                writer.writerow({'run_id':result['run_id'],'data_kind':result['data_kind'],'profile':result['profile'],
                    'case_index':row['case_index'],'accepted':row['accepted'],'stage':stage,'elapsed_ns':elapsed,
                    'requested_backend':backend.requested,'actual_backend':backend.actual})
    print(dump({'output':str(args.output),'accepted_cases':len(rows),'data_kind':result['data_kind'],'complete_protocol':False}),end='')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('preflight',help='Read this local platform without assuming its hardware')
    p.add_argument('--output',type=Path)
    p=sub.add_parser('validate',help='Check current paper arithmetic and obvious attacks, never certify safety')
    for name in ('d','T','k'):p.add_argument('--'+name,type=int,required=True)
    p.add_argument('--q',type=lambda s:int(s,0),required=True)
    p=sub.add_parser('correctness',help='Run tiny explicit-challenge algebra checks')
    p.add_argument('--output',type=Path,required=True);p.add_argument('--d',type=int,default=2)
    p.add_argument('--k',type=int,default=2);p.add_argument('--cases',type=int,default=4)
    p.add_argument('--seed',type=int,default=20261022)
    p.add_argument('--backend',choices=['cpu-reference','gpu'],default='cpu-reference')
    p.add_argument('--allow-cpu-fallback',action='store_true')
    p=sub.add_parser('protocol-correctness',help='Run tiny complete epochs with explicit TEST ONLY evidence')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--epochs',type=int,default=2)
    p.add_argument('--input-hex',default='007fff')
    p.add_argument('--test-seed',type=int)
    p.add_argument('--correctness-only',action='store_true')
    p.add_argument('--backend',choices=['cpu-reference','gpu'],default='cpu-reference')
    p.add_argument('--allow-cpu-fallback',action='store_true')
    sub.add_parser('benchmark',help='Closed pending approved security parameters and local collection authorization')
    args=parser.parse_args(argv)
    try:
        if args.command=='benchmark':
            parser.error('formal performance collection is not authorized; approved security parameters, real external evidence and prepared platforms are required')
        if args.command=='preflight':
            result=machine_info()
            if args.output:
                args.output.parent.mkdir(parents=True,exist_ok=True)
                with args.output.open('x',encoding='utf-8') as f:f.write(dump(result))
            print(dump(result),end='')
        elif args.command=='validate':
            result=validate_current_parameters(d=args.d,T=args.T,k=args.k,q=args.q)
            print(dump(asdict(result)),end='')
            return 2 if result.status.startswith('rejected') else 0
        elif args.command=='correctness':correctness(args)
        elif args.command=='protocol-correctness':
            from .protocol_run import protocol_correctness
            protocol_correctness(args)
    except (ValueError,OSError,BackendUnavailable) as exc:
        print(str(exc),file=sys.stderr);return 2
    return 0
