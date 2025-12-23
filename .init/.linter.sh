#!/bin/bash
cd /home/kavia/workspace/code-generation/audio-visualizer-platform-190701-190711/audio_visualizer_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

