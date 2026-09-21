"""All project content shown on the page.

Everything a teammate is likely to want to change lives here rather than in the
template: who is on the team, what the milestones contain, which tools the
project uses, and where the course documents live.

**Publishing a deliverable.** Every document below has a ``url`` that starts
empty. An empty url renders as plain greyed-out text marked "not published yet";
the moment you put a link in, it becomes a working hyperlink::

    {"label": "Plan", "url": "https://docs.google.com/document/d/..."}  # external
    {"label": "Plan", "url": "/static/docs/plan.pdf"}                   # in this repo

For a file in this repo, drop it in ``rootview_web/static/docs/`` and link it
with the absolute path above; the server mounts that directory at ``/static``.
Nothing outside this file needs to change, and there is no build step -- the
landing page reads it on every request.
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
                    {"label": "Plan", "url": "docs/senior_project_plan.pdf"},
                    {"label": "Presentation", "url": "docs/RootView_Project_Plan.pptx"},
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


#: The two diagrams in the "How it fits together" section of the landing page.
#:
#: Only the words live here. The shapes themselves -- the stack's boxes and the
#: engine's rings -- are drawn in ``site/templates/page.html`` and matched to the
#: entries below by key, so renaming a key here without renaming it there
#: leaves a shape with no description attached. Adding a layer means adding the
#: shape too; editing a label or a description means editing only this file.
ARCHITECTURE = {
    "stack": {
        "title": "The virtualization stack",
        "summary": (
            "Where a guest actually runs, from the hardware up through the "
            "hypervisor to the VMs themselves. RootView adds no layer here. It "
            "watches this stack from the host side."
        ),
        "layers": {
            "vms": {
                "label": "Guest VMs",
                "desc": (
                    "Independent virtual machines, each with its own guest "
                    "kernel. This is the layer RootView exists to protect: it "
                    "is where an eBPF rootkit runs, and where it hides."
                ),
            },
            "kvm": {
                "label": "Host OS + KVM",
                "desc": (
                    "The host's Linux kernel with the KVM module loaded, "
                    "creating, scheduling and isolating the guests above it. "
                    "RootView runs here, beside the hypervisor rather than "
                    "inside anything it is watching."
                ),
            },
            "hardware": {
                "label": "Hardware",
                "desc": (
                    "The physical machine underneath everything: a CPU with "
                    "virtualization extensions (VT-x or AMD-V), memory and "
                    "storage."
                ),
            },
        },
    },
    "engine": {
        "title": "The detection engine",
        "summary": (
            "RootView's own layers, built outward from the guest. The colour "
            "brightens with each ring: the VM at the centre is opaque, and "
            "every layer around it adds a little more visibility into what is "
            "happening inside."
        ),
        "layers": {
            "vm": {
                "label": "VM",
                "desc": (
                    "The guest being monitored. From inside, a rootkit can "
                    "hide itself from the guest's own tools, so RootView "
                    "treats nothing reported from in here as evidence."
                ),
            },
            "vmi": {
                "label": "VMI",
                "desc": (
                    "Virtual machine introspection, built on LibVMI. Reads the "
                    "guest's memory directly from the host, so a compromised "
                    "guest kernel cannot lie about its own state."
                ),
            },
            "rootview": {
                "label": "RootView",
                "desc": (
                    "The detection logic. Walks the guest memory that VMI "
                    "hands it to enumerate eBPF programs and maps, and checks "
                    "what it finds against known rootkit behaviour."
                ),
            },
            "api": {
                "label": "Python API",
                "desc": (
                    "A researcher-facing interface over the same introspection "
                    "data, for building eBPF analysis and detection tooling "
                    "beyond the checks that ship with the engine."
                ),
            },
            "engine": {
                "label": "Engine",
                "desc": (
                    "Ties the detection logic, VMI and the Python API together "
                    "into one running service. This is the layer the web "
                    "server talks to."
                ),
            },
            "web": {
                "label": "Web server",
                "desc": (
                    "The interface: a dashboard that answers whether anything "
                    "is wrong, and an introspection view for reading the raw "
                    "eBPF state the engine is working from."
                ),
            },
        },
    },
}
