# Copyright (C) 2026 Stuart Pook
# SPDX-License-Identifier: GPL-3.0-or-later
FROM python:3.13-alpine
RUN pip install --no-cache-dir --root-user-action=ignore ovh
ENTRYPOINT ["python"]
CMD ["-c", "print('use script')"]
