"""All project content shown on the landing page.

Everything a teammate is likely to want to change lives here rather than in the
templates: who is on the team, what the milestones contain, which tools the
project uses, and where the course documents live.

**Publishing a deliverable.** Every document below has a ``url`` that starts
empty. An empty url renders as plain greyed-out text marked "not published yet";
the moment you put a link in, it becomes a working hyperlink. Nothing else has
to change::

    {"label": "Plan", "url": "/static/docs/plan.pdf"},

Any url works -- a path to a file dropped in ``rootview_web/static/docs/``, or a
full link to a Google Doc, a PDF, or a GitHub file.

Note that this is a Python module, so the web server has to be restarted before
an edit here shows up. Running with ``uvicorn ... --reload`` does that for you.
"""

from __future__ import annotations

PROJECT_NAME = "RootView - a KVM-based eBPF malware detection engine"

#: (name, email) in the order they should appear.
TEAM = [
    ("Luis Abraham", "labrahamesco2024@my.fit.edu"),
    ("Dylin Irons", "dirons2024@my.fit.edu"),
    ("Dominick Morales", "dmorales2024@my.fit.edu"),
    ("Braiden Ames", "bames2024@my.fit.edu"),
]

ADVISOR = ("Dr. Eraldo Ribeiro", "eribeiro@fit.edu")

#: Deliverables by semester. Add a semester by appending another entry here.
SEMESTERS = [
    {
        "label": "First Semester",
        "rows": [
            {
                "milestone": "Plan",
                "due": "Aug 31",
                "documents": [
                    {"label": "Plan", "url": "https://docs.google.com/document/d/1X2HVOF_cRx9IzFaK1CwSO_rhBEuO-SpnqIVeKuTrdmY/edit?usp=sharing"},
                    {"label": "Presentation", "url": ""},
                ],
            },
            {
                "milestone": "Milestone 1",
                "due": "Sep 28",
                "summary": "Establishes the basic VMI infrastructure.",
                "tasks": [
                    "Select KVM/QEMU, LibVMI, web framework, and initial eBPF tools",
                    "Create simple tooling for setting up an Ubuntu VM",
                    "Connect to a running guest through LibVMI",
                    "Read physical and virtual guest memory",
                    "Investigate address translation",
                    "Retrieve basic register state",
                    "Begin process introspection",
                    "Serve a basic test page",
                    "Complete the Requirements Document",
                    "Complete the Design Document",
                    "Complete the Test Plan",
                ],
                "documents": [
                    {"label": "Requirement", "url": ""},
                    {"label": "Design", "url": ""},
                    {"label": "Test", "url": ""},
                    {"label": "Presentation", "url": ""},
                    {"label": "Progress Evaluation", "url": ""},
                ],
            },
            {
                "milestone": "Milestone 2",
                "due": "Oct 26",
                "summary": "Expands RootView into a Linux and eBPF introspection platform.",
                "tasks": [
                    "Linux kernel introspection",
                    "BTF/DWARF and kernel symbol investigation",
                    "Process and kernel object enumeration",
                    "eBPF introspection",
                    "Integration of VMI and eBPF observations",
                    "Web interface improvements",
                    "Initial kernel-version testing",
                ],
                "documents": [
                    {"label": "Presentation", "url": ""},
                    {"label": "Progress Evaluation", "url": ""},
                ],
            },
            {
                "milestone": "Milestone 3",
                "due": "Nov 23",
                "summary": "Turns the backend into a reusable research platform.",
                "tasks": [
                    "C/C++ API for VM, OS, memory, and eBPF introspection",
                    "Python bindings",
                    "High-level Python interface",
                    "Error handling and testing",
                    "Linux kernel version compatibility",
                    "Kernel profile improvements",
                    "API documentation",
                    "Stable interface for the future detection engine",
                ],
                "documents": [
                    {"label": "Presentation", "url": ""},
                    {"label": "Progress Evaluation", "url": ""},
                ],
            },
        ],
    },
]


#: (tool, what it is used for) shown in the "Algorithms and tools" section.
TOOLS = [
    ("KVM/QEMU", "Virtualization"),
    ("LibVMI", "Virtual machine introspection"),
    ("Page-table walking", "Address translation"),
    ("BTF/DWARF and kernel profiles", "Interpreting Linux kernel structures"),
    ("eBPF", "Kernel telemetry"),
    ("C/C++", "The VMI backend"),
    ("Python", "The research API and future detection engine"),
    ("Web framework", "The user interface"),
]

#: (challenge, explanation) shown in the "Technical challenges" section.
CHALLENGES = [
    (
        "KVM and VMI",
        "The team has limited experience with KVM and VMI and must learn how to "
        "access guest memory, processor state, and page tables from outside the "
        "guest.",
    ),
    (
        "Linux kernel introspection",
        "Kernel structures change between versions, so RootView must investigate "
        "ways to identify and interpret structures without relying entirely on "
        "hardcoded offsets.",
    ),
    (
        "eBPF malware",
        "The team must learn how eBPF works internally, how it can be abused by "
        "rootkits, and what characteristics of malicious activity can be observed.",
    ),
]
