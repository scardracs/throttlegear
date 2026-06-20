import unittest
import xml.etree.ElementTree as ET
from throttlegear.limits import validate_limits, extract_cpu_limits, extract_gpu_limits

class TestLimits(unittest.TestCase):
    def test_validate_limits_valid(self):
        ac_limits = {
            "ppt_pl1_spl_min": 35,
            "ppt_pl1_spl_max": 125,
            "ppt_pl1_spl_def": 90,
            "nv_temp_target_min": 75,
            "nv_temp_target_max": 87,
        }
        dc_limits = {
            "ppt_pl1_spl_min": 25,
            "ppt_pl1_spl_max": 65,
        }
        warnings = validate_limits(ac_limits, dc_limits, gpu_base_tgp=55)
        self.assertEqual(len(warnings), 0)

    def test_validate_limits_warnings(self):
        # Invalid values to trigger various warnings
        ac_limits = {
            "ppt_pl1_spl_min": 100,
            "ppt_pl1_spl_max": 50,    # min > max
            "ppt_pl1_spl_def": 200,   # def > max
            "nv_temp_target_min": -5, # negative temp
            "nv_tgp_min": 600,        # out-of-bounds TGP
        }
        dc_limits = {
            "ppt_pl1_spl_min": -10,   # negative value
        }
        
        # Test validation with a baseline warning trigger (large base TGP)
        warnings = validate_limits(ac_limits, dc_limits, gpu_base_tgp=250)
        self.assertTrue(any("GPU base TGP" in w for w in warnings))
        self.assertTrue(any("Min limit ppt_pl1_spl_min" in w for w in warnings))
        self.assertTrue(any("Default limit ppt_pl1_spl_def" in w for w in warnings))
        self.assertTrue(any("Temperature target nv_temp_target_min" in w for w in warnings))
        self.assertTrue(any("GPU TGP nv_tgp_min" in w for w in warnings))
        self.assertTrue(any("has a negative value" in w for w in warnings))

    def test_extract_cpu_limits(self):
        xml_str = """
        <ThrottlePluginCPUSettings IsEnabled="True">
            <OverclockItems>
                <STAPM IsEnabled="True" LowerLimit="25" UpperLimit="65" Manual="45" DCLowerLimit="15" DCUpperLimit="35" DCManual="25" />
                <PPTLimit IsEnabled="True" LowerLimit="30" UpperLimit="70" Manual="50" DCLowerLimit="20" DCUpperLimit="40" DCManual="30" />
            </OverclockItems>
        </ThrottlePluginCPUSettings>
        """
        elem = ET.fromstring(xml_str)
        
        # Test AC (dc=False)
        ac_limits = extract_cpu_limits(elem, dc=False)
        self.assertEqual(ac_limits["ppt_pl1_spl_min"], 25)
        self.assertEqual(ac_limits["ppt_pl1_spl_max"], 65)
        self.assertEqual(ac_limits["ppt_pl1_spl_def"], 45)
        self.assertEqual(ac_limits["ppt_pl2_sppt_min"], 30)
        self.assertEqual(ac_limits["ppt_pl2_sppt_max"], 70)
        self.assertEqual(ac_limits["ppt_pl2_sppt_def"], 50)
        
        # Test DC (dc=True)
        dc_limits = extract_cpu_limits(elem, dc=True)
        self.assertEqual(dc_limits["ppt_pl1_spl_min"], 15)
        self.assertEqual(dc_limits["ppt_pl1_spl_max"], 35)
        self.assertEqual(dc_limits["ppt_pl1_spl_def"], 25)
        self.assertEqual(dc_limits["ppt_pl2_sppt_min"], 20)
        self.assertEqual(dc_limits["ppt_pl2_sppt_max"], 40)
        self.assertEqual(dc_limits["ppt_pl2_sppt_def"], 30)

    def test_extract_gpu_limits(self):
        xml_str = """
        <ThrottlePluginGPUSettings IsEnabled="True">
            <NonSLIOverclockItems>
                <NBThermalTarget IsEnabled="True" LowerLimit="75" UpperLimit="87" DCLowerLimit="70" DCUpperLimit="85" />
                <DynamicBoost IsEnabled="True" LowerLimit="5" UpperLimit="25" />
            </NonSLIOverclockItems>
            <NonSLITGPItems>
                <TGPItem IsEnabled="True" Level0="-10" Level1="0" Level2="10" />
            </NonSLITGPItems>
        </ThrottlePluginGPUSettings>
        """
        elem = ET.fromstring(xml_str)
        
        # Test AC (dc=False)
        ac_limits = extract_gpu_limits(elem, gpu_base_tgp=60, dc=False)
        self.assertEqual(ac_limits["nv_temp_target_min"], 75)
        self.assertEqual(ac_limits["nv_temp_target_max"], 87)
        self.assertEqual(ac_limits["nv_dynamic_boost_min"], 5)
        self.assertEqual(ac_limits["nv_dynamic_boost_max"], 25)
        self.assertEqual(ac_limits["nv_tgp_min"], 50) # 60 + -10
        self.assertEqual(ac_limits["nv_tgp_max"], 70) # 60 + 10
        
        # Test DC (dc=True)
        dc_limits = extract_gpu_limits(elem, gpu_base_tgp=60, dc=True)
        self.assertEqual(dc_limits["nv_temp_target_min"], 70)
        self.assertEqual(dc_limits["nv_temp_target_max"], 85)
        self.assertNotIn("nv_dynamic_boost_min", dc_limits)
        self.assertNotIn("nv_tgp_min", dc_limits)

if __name__ == "__main__":
    unittest.main()
