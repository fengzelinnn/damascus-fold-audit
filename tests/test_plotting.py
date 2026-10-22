"""Rendering tests inspect native editable objects and vector output, not timings."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile
from xml.etree import ElementTree

from damascus_a.aggregate import ValidationError, load_records
from damascus_a import plotting
from damascus_a.plotting import Typography, render
from tests.test_aggregate import record
from damascus_a.aggregate import aggregate


ROOT = Path(__file__).resolve().parents[1]
HAVE_PLOT = all(importlib.util.find_spec(name) for name in ("matplotlib", "pptx"))


@unittest.skipUnless(HAVE_PLOT, "optional plotting dependencies unavailable")
class PlottingTests(unittest.TestCase):
    def test_a4_series_do_not_merge_independent_runs(self):
        resources = {"peak_rss_bytes": 1000, "sampled_peak_vram_bytes": None, "vram_sampling_interval_ns": None}
        rows = [record("A4", resources=resources, run_id="run-one"), record("A4", resources=resources, run_id="run-two"), record("A4", resources=resources, hardware_id="fixture-host-b")]
        panels = plotting._panels(aggregate(rows, "A4"))
        self.assertEqual(len(panels[0]["series"]), 2)
        self.assertIn("run-one", panels[0]["series"][0]["label"])
        self.assertIn("run-two", panels[0]["series"][1]["label"])

    def test_tex_literals_escape_every_special_character(self):
        self.assertEqual(plotting._tex_literal(r"a_b%&#{}\$^~"), r"a\_b\%\&\#\{\}\textbackslash{}\$\textasciicircum{}\textasciitilde{}")

    def test_tex_renderer_escapes_all_label_routes_without_latex(self):
        from matplotlib import pyplot as plt
        from matplotlib.text import Text
        comparison = {"protocol_family": "public_low_storage_por", "guarantee": "x_y & guarantee", "security_model": "50% #model", "source": "source{one}", "cost_scope": r"literal\scope", "parameter_notes": "$not math$"}
        row = record("A5", comparison=comparison)
        figure = aggregate([row], "A5")
        with tempfile.TemporaryDirectory() as tmp, patch("matplotlib.figure.Figure.savefig"), patch("matplotlib.pyplot.close"), patch("damascus_a.plotting._tex_literal", wraps=plotting._tex_literal) as escaping:
            plotting._vector(figure, Path(tmp), "test_banner", "font_legend", Typography(True, "DejaVu Serif", ()), True)
            texts = [t.get_text() for t in plt.gcf().findobj(match=Text)]
            texts.extend(cell.get_text().get_text() for table in plt.gcf().axes[0].tables for cell in table.get_celld().values())
            self.assertIn(r"test\_banner", texts)
            self.assertIn(r"font\_legend", texts)
            self.assertTrue(any(r"public\_low\_storage\_por" in t for t in texts))
            self.assertTrue(any(r"50\% \#model" in t for t in texts))
            self.assertGreater(escaping.call_count, 10)
        plt.close("all")

    def test_tex_axes_legends_categories_and_annotations_use_literal_route(self):
        from matplotlib import pyplot as plt
        records = load_records(ROOT / "fixtures/NON_PAPER_fixture.jsonl")
        for row in records:
            row["hardware_id"] += "_platform%"
            row["run_id"] += "_run&"
            row["profile"] += "_profile{}"
        for name in ("A1", "A2", "A3", "A4"):
            figure = aggregate(records, name)
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp, patch("matplotlib.figure.Figure.savefig"), patch("damascus_a.plotting._tex_literal", wraps=plotting._tex_literal) as escaping:
                plotting._vector(figure, Path(tmp), "test_banner", "font_legend", Typography(True, "DejaVu Serif", ()), True)
                passed = [call.args[0] for call in escaping.call_args_list]
                for panel in plotting._panels(figure):
                    for key in ("title", "x_label", "y_label"):
                        self.assertIn(panel[key], passed)
                    for series in panel["series"]:
                        self.assertIn(series["label"], passed)
                    for label in panel.get("categories", []):
                        self.assertIn(label, passed)
                    for failure in panel.get("failures", []):
                        self.assertIn(f"{failure['status']} @ {failure['x']:g} MiB", passed)
        plt.close("all")
    def test_blank_has_no_invented_chart_values_and_is_editable(self):
        with tempfile.TemporaryDirectory() as tmp, patch("damascus_a.plotting.check_typography", return_value=Typography(False, "DejaVu Serif", ("test unavailable",))):
            manifest = render(tmp)
            self.assertTrue(all(f["empty"] for f in manifest["figures"]))
            self.assertIn("EMPTY LAYOUT", manifest["banner"])
            for name in ("A1", "A2", "A3", "A4", "A5"):
                svg = (Path(tmp) / f"{name}.svg").read_text()
                self.assertIn("EMPTY LAYOUT", svg)
                self.assertIn("PREVIEW FONT FALLBACK", svg)
                self.assertNotIn("<image", svg)
                self.assertTrue((Path(tmp) / f"{name}.pdf").read_bytes().startswith(b"%PDF"))
            with ZipFile(Path(tmp) / "A-group-editable.pptx") as archive:
                self.assertFalse(any(name.startswith("ppt/media/") for name in archive.namelist()))
                self.assertFalse(any(name.startswith("ppt/charts/chart") for name in archive.namelist()))
                slides = [name for name in archive.namelist() if name.startswith("ppt/slides/slide") and name.endswith(".xml")]
                self.assertEqual(len(slides), 5)
                self.assertIn(b"<a:tbl>", archive.read("ppt/slides/slide5.xml"))
                self.assertIn(b"NO DATA", archive.read("ppt/slides/slide1.xml"))
                ns = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main", "p": "http://schemas.openxmlformats.org/presentationml/2006/main"}
                for name in slides:
                    document = ElementTree.fromstring(archive.read(name))
                    for reference in document.findall(".//a:effectRef", ns):
                        self.assertEqual(reference.get("idx"), "0", "theme effects can rasterize during PDF export")
                    for connector in document.findall(".//p:cxnSp", ns):
                        self.assertIsNotNone(connector.find("p:spPr/a:effectLst", ns))

    def test_fixture_charts_are_native_editable_and_prominently_labeled(self):
        records = load_records(ROOT / "fixtures/NON_PAPER_fixture.jsonl")
        with tempfile.TemporaryDirectory() as tmp, patch("damascus_a.plotting.check_typography", return_value=Typography(False, "DejaVu Serif", ("test unavailable",))):
            manifest = render(tmp, records, fixture=True)
            self.assertIn("NON-PAPER", manifest["banner"])
            with ZipFile(Path(tmp) / "A-group-editable.pptx") as archive:
                charts = [name for name in archive.namelist() if name.startswith("ppt/charts/chart") and name.endswith(".xml")]
                self.assertEqual(len(charts), 5)
                self.assertTrue(any(name.startswith("ppt/embeddings/") for name in archive.namelist()))
                self.assertFalse(any(name.startswith("ppt/media/") for name in archive.namelist()))
                self.assertIn(b"<c:barChart>", archive.read("ppt/charts/chart2.xml"))
                self.assertIn(b"<c:scatterChart>", archive.read("ppt/charts/chart1.xml"))
                self.assertIn(b"pattFill", archive.read("ppt/charts/chart2.xml"))
                for i in range(1, 6):
                    self.assertIn(b"NON-PAPER", archive.read(f"ppt/slides/slide{i}.xml"))

    def test_fixture_needs_explicit_opt_in_and_never_publication(self):
        records = load_records(ROOT / "fixtures/NON_PAPER_fixture.jsonl")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValidationError, "require --fixture"):
                render(tmp, records)
            with self.assertRaisesRegex(ValidationError, "mutually exclusive"):
                render(tmp, records, fixture=True, publication=True)

    def test_publication_fonts_fail_closed_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp, patch("damascus_a.plotting.check_typography", return_value=Typography(False, "DejaVu Serif", ("newtxmath.sty",))):
            target = Path(tmp) / "must-not-be-created"
            with self.assertRaisesRegex(ValidationError, "publication typography unavailable: newtxmath.sty"):
                render(target, publication=True)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
