"""Shared opaque dataset revision contract used by Collector API envelopes."""

import re


REVISION_PATTERN = re.compile(r"^ds_[a-f0-9]{2,77}$")
