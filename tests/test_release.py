import importlib.util
from pathlib import Path
import tempfile
import unittest


def release_module():
    path=Path(__file__).resolve().parents[1]/'scripts/package_release.py'
    spec=importlib.util.spec_from_file_location('package_release',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class ReleaseTests(unittest.TestCase):
    def test_allowlist_excludes_sources_logs_and_credentials(self):
        m=release_module()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ['README.md','damascus_a/a.py','sources/paper/manifest.json','sources/paper/main.pdf','sources/legacy/code.rs','runs/raw.json','docs/.env','docs/normal.md']:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('safe')
            files=m.collect_files(root)
            self.assertEqual({str(p.relative_to(root)) for p in files},{'README.md','damascus_a/a.py','sources/paper/manifest.json','docs/normal.md'})

    def test_secret_scan_fails_closed(self):
        m=release_module()
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'a.py'
            p.write_text('credential = '+ 'ghp_' + 'a'*36)
            with self.assertRaises(ValueError): m.scan_files([p])

    def test_symlinks_not_packaged(self):
        m=release_module()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'docs').mkdir(); (root/'private').write_text('sensitive')
            try: (root/'docs/linked').symlink_to(root/'private')
            except OSError: self.skipTest('symlinks unavailable')
            with self.assertRaises(ValueError): m.collect_files(root)

    def test_private_drive_locators_reject_public_package(self):
        m=release_module()
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'research.md'
            p.write_text('https://drive.google.com/'+'file/d/private-source/view')
            with self.assertRaises(ValueError): m.scan_files([p])

    def test_allowlisted_root_file_cannot_cross_symlinked_ancestor(self):
        m=release_module()
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);root=base/'root';root.mkdir()
            outside=base/'outside';(outside/'paper').mkdir(parents=True)
            (outside/'paper/manifest.json').write_text('private contents')
            try:(root/'sources').symlink_to(outside,target_is_directory=True)
            except OSError:self.skipTest('symlinks unavailable')
            with self.assertRaises(ValueError):m.collect_files(root)
