# Portfolio demo: synthetic brute-force workflow

1. Start the backend and frontend using the root README.
2. Click **Run demo** in the dashboard (or run `python -m simulator.brute_force_simulator`).
3. The simulator submits 30 failed-login records for `demo-admin` from `192.0.2.10`, a documentation-only TEST-NET address.
4. Open the resulting high-severity DET-001 alert and review the evidence timeline.
5. Select **Investigate alert** to create a structured local analysis report.
6. Export the report as JSON from the investigation panel.

All records are synthetic. This demonstration does not perform authentication attempts. Delete the local `data/sentinel.db` file to reset the demo.
