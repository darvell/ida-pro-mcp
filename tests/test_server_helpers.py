import importlib
import unittest
from unittest import mock


server = importlib.import_module("ida_pro_mcp.server")


class FormatGlobalsTests(unittest.TestCase):
    def test_format_globals_compact_groups_entries(self):
        sample = [
            {"kind": "data_read", "at": "0x1000", "target": "0x2000", "name": "gVar"},
            {"kind": "data_read", "at": "0x1004", "target": "0x2004"},
            {"kind": "data_write", "at": "0x1010", "target": "0x3000", "name": "dst"},
        ]

        grouped = server._format_globals_compact(sample)

        self.assertSetEqual(set(grouped), {"data_read", "data_write"})
        self.assertEqual(grouped["data_read"][0], ["0x1000", "0x2000", "gVar"])
        self.assertEqual(grouped["data_read"][1], ["0x1004", "0x2004"])
        self.assertEqual(grouped["data_write"][0][-1], "dst")


class SplitPseudocodeTests(unittest.TestCase):
    def test_split_handles_string(self):
        self.assertEqual(server._split_pseudocode_lines("line1\nline2"), ["line1", "line2"])

    def test_split_handles_list(self):
        self.assertEqual(server._split_pseudocode_lines(["a", "b"]), ["a", "b"])

    def test_split_handles_none(self):
        self.assertEqual(server._split_pseudocode_lines(None), [])


class CheckConnectionTests(unittest.TestCase):
    def test_check_connection_no_instances(self):
        with mock.patch.object(server.InstanceManager, "list", new=classmethod(lambda cls: [])):
            result = server.check_connection()

        self.assertFalse(result["connected"])
        self.assertEqual(result["total_instances"], 0)
        self.assertIn("note", result)

    def test_check_connection_with_metadata(self):
        instance_record = {"database": "sample.i64", "_socket": "/tmp/test.sock", "status": "ready"}
        with mock.patch.object(server.InstanceManager, "list", new=classmethod(lambda cls: [instance_record])):
            with mock.patch.object(server, "make_jsonrpc_request", side_effect=self._fake_metadata_call):
                result = server.check_connection()

        self.assertTrue(result["connected"])
        self.assertEqual(result["total_instances"], 1)
        entry = result["instances"][0]
        self.assertEqual(entry["processor"], "metaproc")
        self.assertEqual(entry["bitness"], 64)

    @staticmethod
    def _fake_metadata_call(database, method, *_, **__):
        assert database == "sample.i64"
        assert method == "system.info"
        return {
            "module": "sample",
            "database": "sample.i64",
            "ida_version": "9.2",
            "ida_major": 9,
            "processor": "metaproc",
            "bitness": 64,
            "api_style": "ida_* modules",
        }


if __name__ == "__main__":
    unittest.main()
