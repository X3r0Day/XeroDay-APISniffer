import warnings


warnings.filterwarnings(
    "ignore",
    message=r".*doesn't match a supported version.*",
    category=Warning,
    module=r"requests(\..*)?",
)

import requests as requests  # noqa: E402

