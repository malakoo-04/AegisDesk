import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

BASE_URL = "http://127.0.0.1:8000"
MESSAGE = "A" * 2001

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


def main():
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "test": "oversized_input",
        "input_length": len(MESSAGE),
        "target": BASE_URL,
    }

    try:
        with httpx.Client(timeout=100) as client:
            health_response = client.get(f"{BASE_URL}/health")
            health_response.raise_for_status()
            health = health_response.json()

            result["defenses_enabled"] = health["defenses_enabled"]
            result["model"] = health["model"]

            print("AegisDesk oversized-input test")
            print(f"Defense mode: {health['defenses_enabled']}")
            print(f"Model: {health['model']}")
            print(f"Input length: {len(MESSAGE)} characters")

            started = time.perf_counter()

            response = client.post(
                f"{BASE_URL}/chat",
                json={
                    "message": MESSAGE,
                    "user_id": "analyst",
                },
            )

            result["http_status"] = response.status_code
            result["latency_ms"] = round(
                (time.perf_counter() - started) * 1000
            )
            result["response"] = response.text[:1000]

            if response.status_code == 400:
                result["outcome"] = "rejected"
                print("OBSERVED: request rejected with HTTP 400.")
            elif response.status_code == 200:
                result["outcome"] = "accepted"
                print("OBSERVED: request accepted with HTTP 200.")
            else:
                result["outcome"] = "technical_error"
                print(f"TECHNICAL RESULT: HTTP {response.status_code}")

    except (httpx.HTTPError, ValueError) as exc:
        result["outcome"] = "technical_error"
        result["error"] = repr(exc)
        print(f"TECHNICAL ERROR: {exc}")

    mode = "hardened" if result.get("defenses_enabled") else "baseline"
    output = RESULTS_DIR / f"resource_limit_{mode}.json"

    # Exclusive creation prevents accidental overwriting of earlier evidence.
    suffix = 1
    while output.exists():
        output = RESULTS_DIR / f"resource_limit_{mode}_{suffix}.json"
        suffix += 1

    with output.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    print(f"Evidence saved to: {output}")


if __name__ == "__main__":
    main()