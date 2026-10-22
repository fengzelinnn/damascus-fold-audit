import importlib.util
from pathlib import Path
import unittest


def module():
    spec=importlib.util.spec_from_file_location('export_preview',Path(__file__).resolve().parents[1]/'scripts/export_ppt_preview.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


class ExportPreviewTests(unittest.TestCase):
    def test_only_marked_preview_is_exported(self):
        m=module()
        m.check_preview({'publication':False,'banner':'EMPTY LAYOUT — NO MEASUREMENTS'})
        m.check_preview({'publication':False,'banner':'NON-PAPER — SYNTHETIC TEST FIXTURE'})
        for invalid in ({'publication':True,'banner':'EMPTY LAYOUT'}, {'publication':False,'banner':'DATA PRECONDITIONS CHECKED'}, {}):
            with self.assertRaises(ValueError):m.check_preview(invalid)

    def test_raster_images_or_unknown_inventory_reject(self):
        m=module();header='page   num  type   width height\n----------------------------\n'
        m.check_vector_inventory(header)
        with self.assertRaises(ValueError):m.check_vector_inventory(header+'1 0 image 34 859 gray\n')
        with self.assertRaises(ValueError):m.check_vector_inventory('unrecognized output')
