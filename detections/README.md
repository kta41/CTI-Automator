# Detection proposals

This directory holds YARA (`.yar`) and SIGMA (`.yml`) rule proposals generated
by `cti-automator generate-detections`. Every file is a **proposal** until a
human reviewer approves it in a pull request; nothing here is deployed
automatically.

Workflow:

1. Generate proposals locally from an analyzed report:
   `cti-automator generate-detections report.pdf --yara-dir detections --sigma-dir detections`
2. Open a pull request touching this directory; the `Detection rules GitOps gate`
   workflow validates structure, syntax and the required proposal markers.
3. A reviewer compiles YARA rules with `yara` and checks SIGMA rules with
   `sigma-cli` before approving.
4. Merged rules are treated as approved; removing a rule requires a dedicated
   pull request with a documented rationale.
