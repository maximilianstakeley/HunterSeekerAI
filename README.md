# HunterSeekerAI

## Adaptive Systems Optimization & Learning Engine

HunterSeekerAI is a Python-based adaptive systems optimization project designed to monitor system behavior, detect anomalies, investigate potential causes, select corrective actions, execute those actions safely, verify their outcomes, and learn from historical execution experience.

The project combines **deterministic systems engineering with machine learning**. Rather than treating machine learning as the entire system, ML models are used as learned components within a larger algorithmic architecture.

> **Core concept:** Monitor → Detect → Investigate → Decide → Act → Verify → Learn → Adapt

---

## Project Overview

HunterSeekerAI was built as an exploration of how an intelligent software system could move beyond passive monitoring and toward **closed-loop systems optimization**.

The system is designed around several stages:

```text
                    ┌─────────────────────┐
                    │   System / Dataset  │
                    │       Inputs        │
                    └──────────┬──────────┘
                               ↓
                    ┌─────────────────────┐
                    │     Monitoring      │
                    │        V0           │
                    └──────────┬──────────┘
                               ↓
                    ┌─────────────────────┐
                    │ Anomaly Detection   │
                    │        V1           │
                    └──────────┬──────────┘
                               ↓
                    ┌─────────────────────┐
                    │   Investigation     │
                    │        V2           │
                    └──────────┬──────────┘
                               ↓
                    ┌─────────────────────┐
                    │ Decision / Planning │
                    │       V3+           │
                    └──────────┬──────────┘
                               ↓
                    ┌─────────────────────┐
                    │     Execution       │
                    │       V4+           │
                    └──────────┬──────────┘
                               ↓
                    ┌─────────────────────┐
                    │     Verification    │
                    │        V5           │
                    └──────────┬──────────┘
                               ↓
                ┌──────────────┴──────────────┐
                ↓                             ↓
       ┌─────────────────┐           ┌─────────────────┐
       │ Feedback/Learning│           │ Historical      │
       │     V6–V9       │           │ Experience V10  │
       └────────┬────────┘           └────────┬────────┘
                └──────────────┬──────────────┘
                               ↓
                     Future Decisions
```

The architecture is intentionally separated into stages so that individual components can be tested, evaluated, modified, and eventually replaced without requiring the entire system to be rewritten.

---

# Architecture

HunterSeekerAI uses a modular architecture rather than a single monolithic program.

The major architectural layers include:

```text
Input / Telemetry
       ↓
Monitoring
       ↓
Anomaly Detection
       ↓
Investigation
       ↓
Decision Engine
       ↓
Execution
       ↓
Verification
       ↓
Feedback + Experience
       ↓
Learning / Adaptation
```

This separation allows deterministic system logic, machine-learning models, execution mechanisms, and historical experience to remain distinct components.

### Algorithm vs. Machine Learning

One of the central architectural principles of the project is that the **algorithm and ML models are not the same thing**.

```text
HunterSeekerAI Algorithm
│
├── Monitoring
├── Detection
├── Investigation
├── Decision Logic
├── Execution
├── Verification
├── Feedback
└── Experience / Memory
          ↑
          │
    ML Model Outputs
          ↑
          │
   Training Pipeline
          ↑
          │
     Multiple Datasets
```

The algorithm provides the overall control structure.

Machine learning provides learned parameters or predictions that can inform portions of that structure.

This separation makes it possible to evaluate whether improvements come from the underlying algorithm, the learned model, or the interaction between the two.

---

# Python Engineering

## Modular Architecture

The project is divided into functional components rather than relying on one large script.

This allows individual components to be:

* developed independently
* tested independently
* replaced without rewriting the entire system
* reused by other components
* evaluated against controlled inputs
* extended as the architecture evolves

The V0–V10 progression represents the development of the system's capabilities over time.

---

## Database Integration

HunterSeekerAI uses persistent storage to maintain information required by the system.

Database-backed information can include:

* system state
* configuration
* execution history
* action statistics
* learned experience
* model-related information
* historical outcomes

Persistent storage allows the system to retain information between executions instead of treating every run as an isolated event.

---

## Logging

Logging is incorporated throughout the system to provide visibility into execution and system behavior.

Logging supports:

* operational monitoring
* debugging
* error diagnosis
* execution tracing
* experiment analysis
* verification of system behavior

The goal is to make system behavior observable rather than relying solely on final program output.

---

## Error Handling

The project incorporates explicit error handling so that failures can be identified and handled rather than silently propagating through the system.

Error handling is particularly important for an optimization system because an incorrect action can potentially be more damaging than taking no action.

The architecture therefore emphasizes:

```text
Detect failure
     ↓
Record failure
     ↓
Prevent unsafe continuation
     ↓
Recover / rollback when possible
     ↓
Verify resulting state
```

---

## Testing

Testing is used to verify individual components and system behavior.

Testing priorities include:

* expected inputs
* invalid inputs
* edge cases
* anomaly conditions
* execution behavior
* database behavior
* model outputs
* verification logic
* failure conditions

As the system evolves, testing is intended to move increasingly toward automated regression testing so that changes to one component do not silently break another.

---

## Git / GitHub

Git is used for version control throughout development.

The repository provides a history of:

* algorithm development
* architectural changes
* debugging
* experimentation
* ML pipeline development
* model changes
* documentation
* feature additions

GitHub serves as the project's development and portfolio platform while also providing a reproducible record of the project's evolution.

---

## Command-Line Interfaces

The project includes command-line interfaces for running and evaluating components without requiring changes directly to the source code.

CLI functionality supports tasks such as:

```text
Training
Evaluation
Demonstration
Simulation
Statistics
Continuous execution
Dataset processing
```

Example:

```bash
python V10_ExecutionLearning.py --demo --cycles 10 --stats
```

This approach makes experiments reproducible and allows the same code to be executed with different configurations.

---

# Machine Learning Engineering

## Multiple Datasets

The ML pipeline is designed to work across multiple cybersecurity/network datasets rather than relying on a single source.

The training workflow incorporates datasets including:

* UNSW-NB15
* CIC-IDS2017
* CSE-CIC2018
* TON_IoT
* BoT-IoT

Using multiple datasets provides a more demanding evaluation environment than training and evaluating exclusively on one dataset.

It also introduces challenges involving:

* different schemas
* different feature representations
* different label structures
* class imbalance
* different distributions
* dataset-specific artifacts

The preprocessing layer is therefore responsible for creating a common representation suitable for downstream training.

---

# Data Preprocessing

Raw datasets are not assumed to be immediately suitable for machine learning.

The preprocessing pipeline handles operations such as:

```text
Raw Dataset
    ↓
Schema Inspection
    ↓
Column Normalization
    ↓
Data Cleaning
    ↓
Type Conversion
    ↓
Missing-Value Handling
    ↓
Feature Preparation
    ↓
Label Preparation
    ↓
Training Dataset
```

The preprocessing system is designed to process large datasets without requiring every dataset to exist simultaneously in memory.

---

# Feature Engineering

Feature engineering transforms raw system/network measurements into representations that can be used by machine-learning models.

The process considers information such as:

* network behavior
* resource utilization
* traffic characteristics
* connection behavior
* temporal information
* statistical characteristics
* anomaly-related measurements

Feature engineering is treated as part of the model-development pipeline rather than simply passing raw data directly into a classifier.

---

# Model Training

The training pipeline converts processed datasets into learned models.

The general workflow is:

```text
Datasets
   ↓
Preprocessing
   ↓
Feature Engineering
   ↓
Train / Validation Data
   ↓
Model Training
   ↓
Evaluation
   ↓
Model Selection
   ↓
Persisted Model
```

Training is separated from execution so that models can be trained independently and subsequently loaded by the HunterSeekerAI system.

---

# Model Evaluation

Model performance is evaluated using quantitative measurements rather than assuming that successful training means successful deployment.

Evaluation can consider metrics such as:

* accuracy
* precision
* recall
* F1 score
* confusion matrix
* class-level performance
* false positives
* false negatives

Particular attention is given to false positives and false negatives because anomaly-detection systems operate under asymmetric consequences.

---

# Model Persistence

Trained models can be persisted as artifacts so that the model does not need to be retrained every time the system starts.

This creates a separation between:

```text
Training Environment
        ↓
   Model Artifact
        ↓
Execution / Inference Environment
```

This is an important step toward treating the ML component as an actual deployable software component rather than only an experimental notebook or training script.

---

# Large Dataset Handling

The project is designed with large datasets in mind.

Rather than assuming that all data can be loaded into memory simultaneously, the preprocessing pipeline supports techniques such as:

* chunked processing
* streaming-style ingestion
* incremental processing
* temporary intermediate data
* dataset-specific preprocessing

This allows the system to work toward scaling beyond small demonstration datasets.

---

# Systems Thinking

HunterSeekerAI is designed around a closed-loop systems perspective.

## 1. Monitoring

The system observes relevant system behavior and measurements.

```text
System State
     ↓
Telemetry
     ↓
Monitoring
```

Monitoring establishes the information required for downstream analysis.

---

## 2. Anomaly Detection

The system identifies conditions that differ from expected behavior.

An anomaly does not automatically mean that a corrective action should occur.

Instead:

```text
Anomaly
   ↓
Investigation
```

This distinction is important because unusual behavior can be legitimate.

---

## 3. Investigation

Investigation attempts to determine what caused or contributed to an observed condition.

The goal is to move beyond:

> "Something is wrong."

toward:

> "What changed, why did it change, and what evidence supports that conclusion?"

---

## 4. Decision-Making

The decision layer evaluates available evidence and determines whether an intervention is justified.

Potential outcomes include:

```text
No Action
Optimize
Reconfigure
Recover
Isolate
Remove
Escalate
```

The system should not treat every anomaly as requiring immediate intervention.

---

## 5. Execution

When an action is justified, the execution layer carries out the selected operation.

Execution is deliberately separated from detection and decision-making so that an anomaly does not automatically become a system modification.

---

## 6. Verification

After an action is performed, the system evaluates whether the desired outcome actually occurred.

```text
Action
  ↓
System State Changes
  ↓
Verification
  ↓
Success / Failure
```

This creates an important feedback boundary.

A successful action is not assumed merely because the command executed successfully.

---

## 7. Feedback

Execution outcomes provide information that can be fed back into future decisions.

```text
Decision
   ↓
Action
   ↓
Outcome
   ↓
Feedback
   ↓
Future Decision
```

This creates the foundation for adaptive behavior.

---

## 8. Historical Experience

V10 introduces persistent execution experience and statistics.

Instead of treating every decision as independent, the system can retain information about previous actions and their outcomes.

Conceptually:

```text
Current Situation
       +
Historical Experience
       +
Current Evidence
       ↓
Future Decision
```

This is the foundation for eventually developing more sophisticated adaptive policies.

---

# Engineering Judgment

## Dry-Run Execution

The system supports simulated execution so that decisions can be evaluated without immediately modifying a real system.

This provides a safety boundary between:

```text
Decision
   ↓
Simulation
   ↓
Evaluation
```

and:

```text
Decision
   ↓
Real Execution
```

This distinction is important while developing and testing autonomous optimization behavior.

---

## Rollback

Where an operation changes system state, the architecture considers the possibility that the action may produce an undesirable result.

The intended control loop is:

```text
Before State
     ↓
Action
     ↓
After State
     ↓
Verification
     ↓
Success ─────→ Keep Change
     │
     └── Failure → Recover / Rollback
```

Rollback is therefore treated as part of the control architecture rather than as an afterthought.

---

## Safety Constraints

Autonomous optimization requires constraints.

The system is designed around the principle that:

> **The ability to identify a potential optimization does not automatically justify executing it.**

Safety mechanisms can include:

* dry-run mode
* execution flags
* validation
* constrained actions
* state verification
* failure handling
* rollback mechanisms
* explicit separation between analysis and execution

---

# Deterministic Logic vs. Learned Behavior

A major design principle of HunterSeekerAI is separating deterministic system behavior from machine-learned behavior.

```text
                 HunterSeekerAI
                       │
          ┌────────────┴────────────┐
          ↓                         ↓
   Deterministic Logic        Learned Behavior
          │                         │
   Rules / Constraints       ML Predictions
   Verification              Learned Parameters
   Safety                    Historical Patterns
   Execution Control         Experience
          │                         │
          └────────────┬────────────┘
                       ↓
                 Decision Process
                       ↓
                    Action
```

This separation makes the system easier to reason about and provides a mechanism for evaluating whether learned behavior improves the overall system rather than simply assuming that a more complex model is better.

---

# Development Philosophy

HunterSeekerAI is being developed incrementally.

Rather than attempting to create a fully autonomous system immediately, functionality is introduced in stages:

```text
V0
Monitoring
  ↓
V1
Anomaly Detection
  ↓
V2
Investigation
  ↓
V3–V5
Decision → Execution → Verification
  ↓
V6–V9
Feedback / Adaptation / Learning
  ↓
V10
Execution Experience + Historical Feedback
```

Each stage provides a foundation for the next.

This approach allows individual assumptions and components to be tested before increasing system complexity.

---

# Current Status

HunterSeekerAI is an active research and engineering project.

Current development includes:

* modular Python architecture
* persistent system state
* logging
* error handling
* simulation/dry-run execution
* execution experience
* historical action statistics
* multi-dataset preprocessing
* feature engineering
* machine-learning training
* model evaluation
* persisted model artifacts
* large-dataset processing
* Git/GitHub version control
* command-line experimentation

Future development focuses on improving the interaction between the deterministic algorithm, machine-learning components, historical experience, and adaptive decision-making.

---

# Why This Project Exists

HunterSeekerAI is an engineering exploration into a broader question:

> **Can software move from observing system problems toward safely identifying, evaluating, correcting, and learning from those problems?**

The project therefore combines concepts from:

* software engineering
* machine learning
* systems engineering
* cybersecurity
* automation
* optimization
* feedback systems
* decision theory

The long-term objective is to develop increasingly capable adaptive systems while maintaining observability, validation, and safety constraints.

---

# Technology Stack

**Languages**

* Python

**Software Engineering**

* Git
* GitHub
* SQLite / database persistence
* CLI tooling
* Logging
* Automated testing

**Machine Learning**

* Python ML ecosystem
* Feature engineering
* Classification
* Model evaluation
* Model persistence

**Data Engineering**

* Chunked dataset processing
* Multi-dataset normalization
* Large dataset handling
* Intermediate data processing

---

# Repository Structure

```text
HunterSeekerAI/
│
├── V0–V10 algorithm components
├── PreprocessData.py
├── ML training / evaluation components
├── tests/
├── artifacts/
├── data/
├── database / persistence components
├── configuration
├── requirements.txt
└── README.md
```

The repository will continue to evolve as the architecture develops.

---

# Disclaimer

HunterSeekerAI is an experimental engineering project.

The system is being developed incrementally, and not every component represents production-ready autonomous infrastructure. Real-world deployment would require substantially more testing, security analysis, failure-mode analysis, authorization controls, monitoring, and validation.

---

# Author

**Maximilian Stakeley**

HunterSeekerAI is an independent software and machine-learning engineering project developed to explore adaptive systems optimization, machine learning, automation, and intelligent decision-making.
