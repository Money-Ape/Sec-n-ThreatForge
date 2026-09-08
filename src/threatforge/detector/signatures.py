TEST_SIGNATURES = {
    "TF_TEST_MARKER": {
        "description": (
            "Sec-n-ThreatForge controlled test marker"
        ),
        "severity": 10,
        "category": "test",
    },

    "TF_SUSPICIOUS_PATTERN": {
        "description": (
            "Controlled suspicious-pattern marker"
        ),
        "severity": 20,
        "category": "test",
    }
}

SUSPICIOUS_STRINGS = {
    "powershell.exe": {
        "description": "PowerShell execution reference",
        "severity": 15,
    },

    "cmd.exe": {
        "description": "Windows command interpreter reference",
        "severity": 10,
    },

    "wscript.exe": {
        "description": "Windows Script Host reference",
        "severity": 15,
    },

    "cscript.exe": {
        "description": "Windows Script Host reference",
        "severity": 15,
    },

    "rundll32.exe": {
        "description": "Rundll32 execution reference",
        "severity": 15,
    },

    "regsvr32.exe": {
        "description": "Regsvr32 execution reference",
        "severity": 15,
    }
}