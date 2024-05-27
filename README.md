# IntrusionDetectionSystem

An Intrusion Detection System (IDS) application implemented in Python.

## Features

- Real-time network monitoring/ Protocol analysis
- Signature-based detection (Snort Community rules)
- Threat intel Integration (Alienvault OTX)
- Alert generation and notification

## Installation

1. Create and activate a virtual environment:
    ```sh
    python -m venv venv
    venv\Scripts\activate  # For Windows
    ```

2. Install dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

Run the IDS application:
```sh
python ids.py
