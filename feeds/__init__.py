"""
Feed modules for the Exploit Watch page. See common.py for the contract.

ALL lists the modules in the order rebuild.py fetches them. CORE are the feeds
whose failure aborts the run (nothing is written), as in the original design.
"""

ALL = ["kev", "euvd", "cvelist", "nvd", "github", "certeu", "ncscnl", "circl"]
CORE = {"kev", "cvelist"}
