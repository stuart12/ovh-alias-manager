# Copyright (C) 2026 Stuart Pook
# SPDX-License-Identifier: GPL-3.0-or-later
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir --root-user-action=ignore ovh
COPY sync_aliases.py ./
ENTRYPOINT ["python", "/app/sync_aliases.py"]
