"""
CTS (Compatibility Test Suite) Profile Analyzer
Analyzes and validates CTS compatibility profiles for Android devices.
Determines CTS pass/fail status and identifies compatibility gaps.
"""

import json
import os
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class CTSResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_EXECUTED = "not_executed"
    PARTIAL = "partial"


@dataclass
class CTSModule:
    """A CTS test module."""
    name: str
    description: str
    result: CTSResult
    pass_count: int = 0
    fail_count: int = 0
    total_count: int = 0
    duration_seconds: float = 0.0
    failed_tests: List[str] = field(default_factory=list)


@dataclass
class CTSProfile:
    """CTS compatibility profile."""
    android_version: str
    security_patch_level: str
    device_codename: str
    build_fingerprint: str
    overall_result: CTSResult
    pass_rate: float = 0.0
    modules: List[CTSModule] = field(default_factory=list)
    timestamp: Optional[datetime] = None
    cts_version: Optional[str] = None


# Key CTS compatibility requirements
CTS_REQUIREMENTS = {
    "signature": {
        "name": "Signature Verification",
        "description": "APK signature must be valid",
        "critical": True,
    },
    "keystore": {
        "name": "KeyStore Hardware Support",
        "description": "Hardware-backed KeyStore required for CTS",
        "critical": True,
    },
    "selinux": {
        "name": "SELinux Enforcing",
        "description": "SELinux must be in enforcing mode",
        "critical": True,
    },
    "verified_boot": {
        "name": "Verified Boot",
        "description": "DM-verity must be enabled",
        "critical": True,
    },
    "gms": {
        "name": "GMS Certification",
        "description": "Device must be GMS certified",
        "critical": True,
    },
    "cts_profile": {
        "name": "CTS Compatibility Profile",
        "description": "Must pass CTS on reference configuration",
        "critical": True,
    },
    "vndk": {
        "name": "Vendor NDK Compliance",
        "description": "VNDK version must match",
        "critical": False,
    },
    " treble": {
        "name": "Project Treble",
        "description": "Vendor/system partition separation",
        "critical": False,
    },
}


class CTSConfigParser:
    """Parses CTS configuration and result files."""

    @staticmethod
    def parse_cts_result_log(log_path: str) -> Optional[CTSProfile]:
        """
        Parse a CTS result log file (test_result.xml or similar).
        """
        if not os.path.exists(log_path):
            return None

        try:
            with open(log_path) as f:
                content = f.read()

            # Extract build info
            build_fp = ""
            if "Build Fingerprint" in content:
                match = re.search(r"Build Fingerprint.*?([^\n]+)", content)
                if match:
                    build_fp = match.group(1).strip()

            # Extract version info
            android_ver = ""
            if "Android Version" in content:
                match = re.search(r"Android Version.*?([\d.]+)", content)
                if match:
                    android_ver = match.group(1)

            # Extract test results
            modules = []
            module_matches = re.findall(
                r'<Module name="([^"]+)".*?result="([^"]+)".*?pass="(\d+)".*?fail="(\d+)".*?',
                content, re.DOTALL
            )

            for mod_name, result, passed, failed in module_matches:
                modules.append(CTSModule(
                    name=mod_name,
                    description=mod_name,
                    result=CTSResult(result.lower()),
                    pass_count=int(passed),
                    fail_count=int(failed),
                    total_count=int(passed) + int(failed),
                ))

            # Determine overall result
            overall = CTSResult.PASS
            total_pass = sum(m.pass_count for m in modules)
            total_fail = sum(m.fail_count for m in modules)
            total = total_pass + total_fail
            pass_rate = total_pass / total if total > 0 else 0.0

            if total_fail > 0:
                overall = CTSResult.FAIL
            elif total_pass == 0:
                overall = CTSResult.NOT_EXECUTED
            elif pass_rate >= 0.99:
                overall = CTSResult.PASS

            return CTSProfile(
                android_version=android_ver,
                security_patch_level="",
                device_codename="",
                build_fingerprint=build_fp,
                overall_result=overall,
                pass_rate=pass_rate,
                modules=modules,
            )

        except Exception:
            return None

    @staticmethod
    def generate_compatibility_report(profile: CTSProfile) -> Dict[str, Any]:
        """Generate a compatibility assessment report from CTS profile."""
        # Check each requirement
        requirements_met = {}
        for req_id, req_info in CTS_REQUIREMENTS.items():
            requirements_met[req_id] = {
                "met": False,
                "requirement": req_info["name"],
                "description": req_info["description"],
                "critical": req_info["critical"],
            }

        # Map CTS results to requirements
        for module in profile.modules:
            if "signature" in module.name.lower():
                requirements_met["signature"]["met"] = module.result == CTSResult.PASS
            elif "keystore" in module.name.lower() or "keymaster" in module.name.lower():
                requirements_met["keystore"]["met"] = module.result == CTSResult.PASS
            elif "selinux" in module.name.lower():
                requirements_met["selinux"]["met"] = module.result == CTSResult.PASS
            elif "verity" in module.name.lower() or "verified_boot" in module.name.lower():
                requirements_met["verified_boot"]["met"] = module.result == CTSResult.PASS
            elif "vndk" in module.name.lower():
                requirements_met["vndk"]["met"] = module.result == CTSResult.PASS
            elif "treble" in module.name.lower():
                requirements_met["treble"]["met"] = module.result == CTSResult.PASS

        critical_met = all(
            r["met"] for r in requirements_met.values() if r["critical"]
        )

        return {
            "profile": {
                "android_version": profile.android_version,
                "build_fingerprint": profile.build_fingerprint,
                "overall_result": profile.overall_result.value,
                "pass_rate": profile.pass_rate,
                "total_modules": len(profile.modules),
            },
            "requirements": requirements_met,
            "compatibility_verdict": "COMPATIBLE" if critical_met else "INCOMPATIBLE",
            "critical_requirements_met": critical_met,
            "summary": {
                "total_requirements": len(CTS_REQUIREMENTS),
                "met": sum(1 for r in requirements_met.values() if r["met"]),
                "failed": sum(1 for r in requirements_met.values() if not r["met"] and r["critical"]),
            },
        }


class CTSProfileAnalyzer:
    """
    Analyzes CTS compatibility profiles for Android devices.
    """

    def __init__(self):
        self.parser = CTSConfigParser()

    def analyze_from_file(self, result_log_path: str) -> Optional[Dict[str, Any]]:
        """Analyze CTS results from a log file."""
        profile = self.parser.parse_cts_result_log(result_log_path)
        if profile:
            return self.parser.generate_compatibility_report(profile)
        return None

    def analyze_from_device(self) -> Dict[str, Any]:
        """
        Analyze CTS compatibility from device properties.
        This simulates checking the device without running CTS.
        """
        requirements = {}

        # Check SELinux
        selinux_enforcing = False
        selinux_path = "/sys/fs/selinux/enforce"
        if os.path.exists(selinux_path):
            try:
                with open(selinux_path) as f:
                    selinux_enforcing = f.read().strip() == "1"
            except Exception:
                pass

        requirements["selinux"] = {
            "met": selinux_enforcing,
            "requirement": "SELinux Enforcing",
            "description": "SELinux must be in enforcing mode",
            "critical": True,
        }

        # Check Verified Boot
        verity_enforcing = False
        mounts_path = "/proc/mounts"
        if os.path.exists(mounts_path):
            try:
                with open(mounts_path) as f:
                    content = f.read()
                    verity_enforcing = "/system" in content and "verity" in content
            except Exception:
                pass

        requirements["verified_boot"] = {
            "met": verity_enforcing,
            "requirement": "Verified Boot (dm-verity)",
            "description": "DM-verity must be enabled for /system",
            "critical": True,
        }

        # Check GMS
        gms_installed = os.path.exists("/system/app/Phonesky/Phonesky.apk") or \
                       os.path.exists("/data/app/com.android.vending")

        requirements["gms"] = {
            "met": gms_installed,
            "requirement": "GMS Certification",
            "description": "Google Mobile Services must be certified",
            "critical": True,
        }

        # Check hardware-backed KeyStore
        ks_hw = os.path.exists("/dev/kiwihw") or os.path.exists("/dev/trusty-ipc-dev")
        requirements["keystore"] = {
            "met": ks_hw,
            "requirement": "Hardware-backed KeyStore",
            "description": "Android KeyStore must be hardware-backed",
            "critical": True,
        }

        critical_met = all(
            r["met"] for r in requirements.values() if r["critical"]
        )

        return {
            "requirements": requirements,
            "compatibility_verdict": "COMPATIBLE" if critical_met else "INCOMPATIBLE",
            "critical_requirements_met": critical_met,
            "analysis_method": "device_properties",
            "summary": {
                "total_requirements": len(requirements),
                "met": sum(1 for r in requirements.values() if r["met"]),
                "failed": sum(1 for r in requirements.values() if not r["met"] and r["critical"]),
            },
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CTS Profile Analyzer")
    parser.add_argument("--result-file", help="Path to CTS result log")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    analyzer = CTSProfileAnalyzer()

    if args.result_file:
        report = analyzer.analyze_from_file(args.result_file)
    else:
        report = analyzer.analyze_from_device()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print("CTS Compatibility Analysis")
        print("=" * 50)
        verdict = report.get("compatibility_verdict", "UNKNOWN")
        icon = "✅" if verdict == "COMPATIBLE" else "❌"
        print(f"Verdict: {icon} {verdict}")
        print(f"Critical Requirements: {report['summary']['met']}/{report['summary']['total_requirements']} met")
        print()
        for req_id, req in report.get("requirements", {}).items():
            icon = "✅" if req["met"] else "❌"
            critical = "[CRITICAL] " if req["critical"] else ""
            print(f"  {icon} {critical}{req['requirement']}: {req['description']}")


if __name__ == "__main__":
    main()
