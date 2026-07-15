"""
Known GMS Certified Device Catalog
Maintains a database of known GMS-certified Android devices.
Used for cross-referencing and validating device certification.
"""

import json
import os
import sqlite3
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class DeviceEntry:
    """A device entry in the catalog."""
    id: Optional[int] = None
    manufacturer: str = ""
    model: str = ""
    codename: str = ""
    region: str = "GLOBAL"
    gms_certified: bool = False
    certification_date: Optional[str] = None
    android_version_at_certification: Optional[str] = None
    security_patch_at_certification: Optional[str] = None
    play_certification_id: Optional[str] = None
    hardware: str = ""  # e.g., "qcom", "mtk", "exynos"
    notes: str = ""


class DeviceCatalog:
    """
    SQLite-backed catalog of GMS-certified devices.
    """

    DB_PATH = "gms_devices.db"

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DB_PATH
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()
        self._seed_default_devices()

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                manufacturer TEXT NOT NULL,
                model TEXT NOT NULL,
                codename TEXT NOT NULL,
                region TEXT DEFAULT 'GLOBAL',
                gms_certified INTEGER DEFAULT 0,
                certification_date TEXT,
                android_version_at_certification TEXT,
                security_patch_at_certification TEXT,
                play_certification_id TEXT,
                hardware TEXT,
                notes TEXT,
                UNIQUE(manufacturer, model, codename, region)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_manufacturer ON devices(manufacturer)
        """)
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _seed_default_devices(self):
        """Seed the catalog with known GMS-certified devices."""
        known_devices = [
            # Google Pixel
            ("Google", "Pixel 8 Pro", "husky", "GLOBAL", True, "2023-10", "14", "2023-10"),
            ("Google", "Pixel 8", "shiba", "GLOBAL", True, "2023-10", "14", "2023-10"),
            ("Google", "Pixel 7 Pro", "cheetah", "GLOBAL", True, "2022-10", "13", "2022-10"),
            ("Google", "Pixel 7", "panther", "GLOBAL", True, "2022-10", "13", "2022-10"),
            ("Google", "Pixel 6 Pro", "raven", "GLOBAL", True, "2021-10", "12", "2021-10"),
            ("Google", "Pixel 6", "oriole", "GLOBAL", True, "2021-10", "12", "2021-10"),
            ("Google", "Pixel 5a", "barbet", "GLOBAL", True, "2021-08", "11", "2021-08"),
            # Samsung Galaxy S series
            ("Samsung", "Galaxy S24 Ultra", "dm3q", "GLOBAL", True, "2024-01", "14", "2024-01"),
            ("Samsung", "Galaxy S23", "dm2q", "GLOBAL", True, "2023-02", "13", "2023-02"),
            ("Samsung", "Galaxy S22", "r0q", "GLOBAL", True, "2022-02", "12", "2022-02"),
            ("Samsung", "Galaxy S21", "o1s", "GLOBAL", True, "2021-01", "11", "2021-01"),
            # OnePlus
            ("OnePlus", "OnePlus 11", "CPH2451", "GLOBAL", True, "2023-01", "13", "2023-01"),
            ("OnePlus", "OnePlus 10T", "CPH2413", "GLOBAL", True, "2022-08", "12", "2022-08"),
            # Xiaomi
            ("Xiaomi", "Xiaomi 13", "fuxi", "GLOBAL", True, "2022-12", "13", "2022-12"),
            ("Xiaomi", "Xiaomi 12", "psyche", "GLOBAL", True, "2022-03", "12", "2022-03"),
            # Sony
            ("Sony", "Xperia 1 V", "PDX-234", "GLOBAL", True, "2023-05", "13", "2023-05"),
            ("Sony", "Xperia 5 IV", "PDX-223", "GLOBAL", True, "2022-09", "12", "2022-09"),
            # ASUS
            ("ASUS", "Zenfone 9", "AI2202", "GLOBAL", True, "2022-07", "12", "2022-07"),
            # Nothing
            ("Nothing", "Phone (1)", "Nothing Phone 1", "GLOBAL", True, "2022-07", "12", "2022-07"),
            # Huawei (NOT certified)
            ("Huawei", "P50 Pro", "HW-DEU", "GLOBAL", False, None, None, None),
            ("Huawei", "Mate 50", "HW-ANE", "GLOBAL", False, None, None, None),
            # Amazon (NOT certified - uses Fire OS)
            ("Amazon", "Fire HD 10", " KFMAWI", "GLOBAL", False, None, None, None),
        ]

        for device in known_devices:
            self.upsert_device(DeviceEntry(
                manufacturer=device[0],
                model=device[1],
                codename=device[2],
                region=device[3],
                gms_certified=device[4],
                certification_date=device[5],
                android_version_at_certification=device[6],
                security_patch_at_certification=device[7],
            ))

    def upsert_device(self, device: DeviceEntry):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO devices (
                manufacturer, model, codename, region,
                gms_certified, certification_date,
                android_version_at_certification, security_patch_at_certification,
                play_certification_id, hardware, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(manufacturer, model, codename, region)
            DO UPDATE SET
                gms_certified = excluded.gms_certified,
                certification_date = excluded.certification_date,
                android_version_at_certification = excluded.android_version_at_certification,
                security_patch_at_certification = excluded.security_patch_at_certification
        """, (
            device.manufacturer, device.model, device.codename, device.region,
            int(device.gms_certified), device.certification_date,
            device.android_version_at_certification, device.security_patch_at_certification,
            device.play_certification_id, device.hardware, device.notes,
        ))
        conn.commit()

    def lookup(
        self,
        manufacturer: Optional[str] = None,
        model: Optional[str] = None,
        codename: Optional[str] = None,
    ) -> List[DeviceEntry]:
        conn = self._get_conn()
        query = "SELECT * FROM devices WHERE 1=1"
        params = []

        if manufacturer:
            query += " AND manufacturer LIKE ?"
            params.append(f"%{manufacturer}%")
        if model:
            query += " AND model LIKE ?"
            params.append(f"%{model}%")
        if codename:
            query += " AND codename LIKE ?"
            params.append(f"%{codename}%")

        query += " ORDER BY manufacturer, model"
        rows = conn.execute(query, params).fetchall()

        return [
            DeviceEntry(
                id=row["id"],
                manufacturer=row["manufacturer"],
                model=row["model"],
                codename=row["codename"],
                region=row["region"],
                gms_certified=bool(row["gms_certified"]),
                certification_date=row["certification_date"],
                android_version_at_certification=row["android_version_at_certification"],
                security_patch_at_certification=row["security_patch_at_certification"],
                play_certification_id=row["play_certification_id"],
                hardware=row["hardware"],
                notes=row["notes"],
            )
            for row in rows
        ]

    def is_certified(
        self,
        manufacturer: str,
        model: str,
        codename: Optional[str] = None,
    ) -> Optional[bool]:
        """Check if a device is in the certified list."""
        conn = self._get_conn()
        query = "SELECT gms_certified FROM devices WHERE manufacturer LIKE ? AND model LIKE ?"
        params = [f"%{manufacturer}%", f"%{model}%"]

        if codename:
            query += " AND codename LIKE ?"
            params.append(f"%{codename}%")

        row = conn.execute(query, params).fetchone()
        if row:
            return bool(row["gms_certified"])
        return None

    def get_report(self) -> Dict[str, Any]:
        conn = self._get_conn()

        total = conn.execute("SELECT COUNT(*) as c FROM devices").fetchone()["c"]
        certified = conn.execute(
            "SELECT COUNT(*) as c FROM devices WHERE gms_certified=1"
        ).fetchone()["c"]

        by_manufacturer = conn.execute("""
            SELECT manufacturer, COUNT(*) as total,
                   SUM(CASE WHEN gms_certified=1 THEN 1 ELSE 0 END) as certified
            FROM devices
            GROUP BY manufacturer
            ORDER BY certified DESC
        """).fetchall()

        return {
            "total_devices": total,
            "certified": certified,
            "uncertified": total - certified,
            "by_manufacturer": [
                {"manufacturer": r["manufacturer"], "total": r["total"], "certified": r["certified"]}
                for r in by_manufacturer
            ],
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="GMS Device Catalog")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lookup_parser = subparsers.add_parser("lookup", help="Look up a device")
    lookup_parser.add_argument("--manufacturer")
    lookup_parser.add_argument("--model")
    lookup_parser.add_argument("--codename")

    check_parser = subparsers.add_parser("check", help="Quick certification check")
    check_parser.add_argument("--manufacturer", required=True)
    check_parser.add_argument("--model", required=True)

    report_parser = subparsers.add_parser("report", help="Generate catalog report")

    add_parser = subparsers.add_parser("add", help="Add a device")
    add_parser.add_argument("--manufacturer", required=True)
    add_parser.add_argument("--model", required=True)
    add_parser.add_argument("--codename", required=True)
    add_parser.add_argument("--certified", action="store_true")

    args = parser.parse_args()

    catalog = DeviceCatalog()

    if args.command == "lookup":
        devices = catalog.lookup(
            manufacturer=args.manufacturer,
            model=args.model,
            codename=args.codename,
        )
        for d in devices:
            status = "✅ GMS" if d.gms_certified else "❌ No GMS"
            print(f"{d.manufacturer} {d.model} ({d.codename}) [{d.region}] {status}")

    elif args.command == "check":
        result = catalog.is_certified(args.manufacturer, args.model)
        if result is None:
            print("UNKNOWN — device not in catalog")
        elif result:
            print("CERTIFIED ✅")
        else:
            print("NOT CERTIFIED ❌")

    elif args.command == "report":
        report = catalog.get_report()
        print(json.dumps(report, indent=2))

    elif args.command == "add":
        device = DeviceEntry(
            manufacturer=args.manufacturer,
            model=args.model,
            codename=args.codename,
            gms_certified=args.certified,
        )
        catalog.upsert_device(device)
        print(f"Added: {args.manufacturer} {args.model}")

    catalog.close()


if __name__ == "__main__":
    main()
