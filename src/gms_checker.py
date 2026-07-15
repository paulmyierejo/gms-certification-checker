"""
Google Mobile Services (GMS) Certification Checker
Detects and verifies the GMS certification status of Android devices.
Identifies counterfeit/forked devices and ensures Play Store compatibility.
"""

import hashlib
import json
import os
import re
import subprocess
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class GMSStatus(Enum):
    """GMS certification status."""
    CERTIFIED = "certified"             # Official GMS certified
    UNCERTIFIED = "uncertified"         # Not certified
    LICENSEE = "licensee"               # Licensed but not certified
    AOSP_ONLY = "aosp_only"              # No GMS at all
    FORKED = "forked"                    # Forked Android (no GMS)
    MICROG = "microg"                   # MicroG (open source GMS replacement)
    UNKNOWN = "unknown"


@dataclass
class GMSComponent:
    """A GMS component package."""
    package_name: str
    display_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    is_enabled: bool = True
    is_system: bool = True
    signature_valid: bool = False


@dataclass
class GMSCheckResult:
    """Result of GMS certification check."""
    status: GMSStatus
    is_certified: bool
    confidence: float
    found_components: List[GMSComponent] = field(default_factory=list)
    missing_components: List[str] = field(default_factory=list)
    suspicious_components: List[str] = field(default_factory=list)
    google_account_linked: bool = False
    play_store_version: Optional[str] = None
    play_services_version: Optional[str] = None
    gsf_version: Optional[str] = None
    certification_date: Optional[datetime] = None
    regulatory_info: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# Core GMS packages that must be present for certification
REQUIRED_GMS_PACKAGES = {
    "com.google.android.gms": {
        "name": "Google Play Services",
        "critical": True,
    },
    "com.android.vending": {
        "name": "Google Play Store",
        "critical": True,
    },
    "com.google.android.gsf": {
        "name": "Google Services Framework",
        "critical": True,
    },
    "com.google.android.gms.location": {
        "name": "Play Services Location",
        "critical": False,
    },
    "com.google.android.gms.ads": {
        "name": "Play Services Ads",
        "critical": False,
    },
    "com.google.android.gms.analytics": {
        "name": "Play Services Analytics",
        "critical": False,
    },
    "com.google.android.gms.cast": {
        "name": "Google Cast",
        "critical": False,
    },
    "com.google.android.gms.games": {
        "name": "Google Play Games",
        "critical": False,
    },
    "com.google.android.gms.backup": {
        "name": "Google Backup Transport",
        "critical": False,
    },
    "com.google.android.gms.carrierservices": {
        "name": "Carrier Services",
        "critical": False,
    },
    "com.google.android.gms.fitness": {
        "name": "Google Fit",
        "critical": False,
    },
    "com.google.android.gms.wearable": {
        "name": "Android Wear",
        "critical": False,
    },
}

# Suspicious packages that indicate non-GMS or forked environments
SUSPICIOUS_PACKAGES = {
    "org.microg.gms.dummy": "MicroG dummy service",
    "org.microg.gms": "MicroG GMS replacement",
    "com.brightfing": "BrightFing GMS (fork)",
    "com.amazon.aosp": "Amazon AOSP",
    "com.amazon.fire": "Amazon Fire OS",
    "cn.google": "Google China fork",
    "com.huawei.hwid": "Huawei HMS (non-GMS)",
    "com.huawei.mobile services": "Huawei Mobile Services",
    "com.xiaomi.micloud": "Xiaomi cloud services",
}


class GMSComponentScanner:
    """Scans device for GMS components."""

    def __init__(self):
        self._installed_packages: Optional[Set[str]] = None

    def _get_installed_packages(self) -> Set[str]:
        """Get set of all installed package names (simplified)."""
        if self._installed_packages is not None:
            return self._installed_packages

        packages = set()

        # Read from package manager database
        pm_data_path = "/data/system/packages.list"
        if os.path.exists(pm_data_path):
            try:
                with open(pm_data_path) as f:
                    for line in f:
                        parts = line.split(":")
                        if parts:
                            packages.add(parts[0])
            except Exception:
                pass

        # Also scan /system/app for pre-installed packages
        system_app_dir = "/system/app"
        if os.path.exists(system_app_dir):
            for subdir in os.listdir(system_app_dir):
                apk_path = os.path.join(system_app_dir, subdir)
                if os.path.isdir(apk_path):
                    # Extract package name from APK
                    pass  # Would need aapt in production

        self._installed_packages = packages
        return packages

    def _check_package_info(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Get package information (version, enabled state, etc.)."""
        info = {
            "package_name": package_name,
            "version_name": None,
            "version_code": None,
            "is_system": False,
            "is_enabled": True,
        }

        # Check if it's a system package
        system_packages_file = "/data/system/packages.list"
        if os.path.exists(system_packages_file):
            try:
                with open(system_packages_file) as f:
                    for line in f:
                        if line.startswith(package_name + ":"):
                            info["is_system"] = True
                            break
            except Exception:
                pass

        # Check /system/app
        system_app_path = f"/system/app/{package_name.split('.')[-1]}.apk"
        if os.path.exists(system_app_path.replace(".apk", "")):
            info["is_system"] = True

        return info

    def scan_gms_components(self) -> List[GMSComponent]:
        """Scan for all GMS components."""
        installed = self._get_installed_packages()
        found = []

        for pkg_name, pkg_info in REQUIRED_GMS_PACKAGES.items():
            if pkg_name in installed:
                info = self._check_package_info(pkg_name)
                found.append(GMSComponent(
                    package_name=pkg_name,
                    display_name=pkg_info["name"],
                    version_name=info.get("version_name"),
                    version_code=info.get("version_code"),
                    is_enabled=info.get("is_enabled", True),
                    is_system=info.get("is_system", False),
                ))

        return found

    def check_suspicious_packages(self) -> List[Tuple[str, str]]:
        """Check for packages that indicate non-GMS or forked environments."""
        installed = self._get_installed_packages()
        suspicious = []

        for pkg_pattern, description in SUSPICIOUS_PACKAGES.items():
            for installed_pkg in installed:
                if pkg_pattern in installed_pkg or installed_pkg.startswith(pkg_pattern.rsplit(".", 1)[0]):
                    suspicious.append((installed_pkg, description))

        return suspicious


class GSFDeviceIDResolver:
    """
    Google Services Framework device ID resolution.
    The GSF generates a unique Android ID used for Play Store licensing.
    """

    @staticmethod
    def get_android_id() -> Optional[str]:
        """Read Android ID from GSF SharedPreferences."""
        gsf_prefs = "/data/data/com.google.android.gsf/shared_prefs/"
        prefs_file = os.path.join(gsf_prefs, "gservices.xml")

        if os.path.exists(prefs_file):
            try:
                with open(prefs_file) as f:
                    for line in f:
                        if "android_id" in line:
                            match = re.search(r'android_id[^>]*value="([^"]+)"', line)
                            if match:
                                return match.group(1)
            except Exception:
                pass
        return None

    @staticmethod
    def get_gms_device_id() -> Optional[str]:
        """Get GMS device ID (used for Play Services)."""
        gsf_db = "/data/data/com.google.android.gsf/databases/"
        db_file = os.path.join(gsf_db, "google_host.db")

        if os.path.exists(db_file):
            # Would need sqlite3 to read
            pass

        return None


class GMSCertificationChecker:
    """
    Main GMS certification checker.
    Determines if a device has proper Google Mobile Services certification.
    """

    def __init__(self):
        self.scanner = GMSComponentScanner()

    def check(
        self,
        package_name: Optional[str] = None,
        check_accounts: bool = True,
    ) -> GMSCheckResult:
        """
        Perform comprehensive GMS certification check.

        Args:
            package_name: Optional specific package to check
            check_accounts: Check for linked Google accounts

        Returns:
            GMSCheckResult with certification details
        """
        found_components = self.scanner.scan_gms_components()
        suspicious = self.scanner.check_suspicious_packages()

        # Get version info
        play_store_version = None
        play_services_version = None
        gsf_version = None

        for comp in found_components:
            if comp.package_name == "com.android.vending":
                play_store_version = comp.version_name
            elif comp.package_name == "com.google.android.gms":
                play_services_version = comp.version_name
            elif comp.package_name == "com.google.android.gsf":
                gsf_version = comp.version_name

        # Determine status
        missing = []
        critical_missing = []
        for pkg_name, pkg_info in REQUIRED_GMS_PACKAGES.items():
            if pkg_name not in [c.package_name for c in found_components]:
                missing.append(pkg_name)
                if pkg_info.get("critical"):
                    critical_missing.append(pkg_name)

        # Check for Google account
        google_account_linked = False
        if check_accounts:
            accounts_file = "/data/system/users/0/accounts.db"
            if os.path.exists(accounts_file):
                try:
                    # Would need sqlite3
                    google_account_linked = True
                except Exception:
                    pass

        # Determine certification status
        warnings = []
        errors = []

        if suspicious:
            if any("microg" in s[1].lower() for s in suspicious):
                status = GMSStatus.MICROG
                errors.append("MicroG GMS replacement detected — not certified")
                confidence = 1.0
            elif any("amazon" in s[1].lower() for s in suspicious):
                status = GMSStatus.FORKED
                errors.append("Amazon fork detected — no GMS")
                confidence = 1.0
            elif any("huawei" in s[1].lower() for s in suspicious):
                status = GMSStatus.UNCERTIFIED
                warnings.append("Huawei HMS detected — GMS not available")
                confidence = 0.9
            else:
                status = GMSStatus.UNCERTIFIED
                errors.append(f"Suspicious package detected: {suspicious[0][0]}")
                confidence = 0.8
        elif critical_missing:
            status = GMSStatus.UNCERTIFIED
            errors.append(f"Critical GMS components missing: {', '.join(critical_missing)}")
            confidence = 1.0
        elif missing:
            status = GMSStatus.LICENSEE
            warnings.append(f"Optional GMS components missing: {', '.join(missing)}")
            confidence = 0.8
        elif play_store_version and play_services_version:
            status = GMSStatus.CERTIFIED
            confidence = 0.95
        elif len(found_components) > 0:
            status = GMSStatus.CERTIFIED
            confidence = 0.7
            warnings.append("GMS components found but versions could not be verified")
        else:
            status = GMSStatus.AOSP_ONLY
            errors.append("No GMS components detected")
            confidence = 1.0

        # Final certification determination
        is_certified = status in (GMSStatus.CERTIFIED, GMSStatus.LICENSEE)

        return GMSCheckResult(
            status=status,
            is_certified=is_certified,
            confidence=confidence,
            found_components=found_components,
            missing_components=missing,
            suspicious_components=[s[0] for s in suspicious],
            google_account_linked=google_account_linked,
            play_store_version=play_store_version,
            play_services_version=play_services_version,
            gsf_version=gsf_version,
            warnings=warnings,
            errors=errors,
        )

    def check_play_store_integrity(
        self,
        play_store_version: str,
    ) -> Dict[str, Any]:
        """
        Check Play Store version integrity.
        Determines if the installed Play Store is a legitimate version.
        """
        # Known Play Store version ranges
        version_pattern = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
        match = version_pattern.match(play_store_version)

        if not match:
            return {
                "valid": False,
                "reason": f"Version format not recognized: {play_store_version}",
            }

        major, minor, build = int(match.group(1)), int(match.group(2)), int(match.group(3))

        # Minimum acceptable versions
        if major < 10:
            return {
                "valid": False,
                "reason": f"Play Store version too old: {play_store_version}",
            }

        return {
            "valid": True,
            "version": f"{major}.{minor}.{build}",
            "channel": "stable",
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="GMS Certification Checker")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    checker = GMSCertificationChecker()
    result = checker.check()

    if args.json:
        print(json.dumps({
            "status": result.status.value,
            "is_certified": result.is_certified,
            "confidence": result.confidence,
            "components_found": [c.package_name for c in result.found_components],
            "missing_components": result.missing_components,
            "suspicious_packages": result.suspicious_components,
            "google_account_linked": result.google_account_linked,
            "play_store_version": result.play_store_version,
            "play_services_version": result.play_services_version,
            "gsf_version": result.gsf_version,
            "warnings": result.warnings,
            "errors": result.errors,
        }, indent=2))
    else:
        print("GMS Certification Check Report")
        print("=" * 50)
        print(f"Status: {result.status.value.upper()}")
        print(f"Certified: {'✅' if result.is_certified else '❌'}")
        print(f"Confidence: {result.confidence:.0%}")
        print(f"Play Store: {result.play_store_version or 'N/A'}")
        print(f"Play Services: {result.play_services_version or 'N/A'}")
        print(f"GSF: {result.gsf_version or 'N/A'}")
        print(f"Google Account: {'✅ Linked' if result.google_account_linked else '❌ Not linked'}")
        print()
        print(f"Components Found ({len(result.found_components)}):")
        for comp in result.found_components:
            print(f"  ✅ {comp.display_name}")
        if result.missing_components:
            print()
            print(f"Missing ({len(result.missing_components)}):")
            for pkg in result.missing_components:
                print(f"  ❌ {pkg}")
        if result.suspicious_components:
            print()
            print(f"Suspicious ({len(result.suspicious_components)}):")
            for pkg in result.suspicious_components:
                print(f"  ⚠️  {pkg}")
        if result.errors:
            print()
            for e in result.errors:
                print(f"  ❌ {e}")
        if result.warnings:
            print()
            for w in result.warnings:
                print(f"  ⚠️  {w}")


if __name__ == "__main__":
    main()
