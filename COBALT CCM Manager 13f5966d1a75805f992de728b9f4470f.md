# COBALT CCM Manager

[**https://github.com/core-ncsrd/CCM-Manager/tree/main**](https://github.com/core-ncsrd/CCM-Manager/tree/main)

# BOM Documentation

[SBOM - Structure - Notes](https://www.notion.so/SBOM-Structure-Notes-13f5966d1a7580629d2ffda8cb0dd207?pvs=21)

[CBOM - Structure - Notes](https://www.notion.so/CBOM-Structure-Notes-13f5966d1a7580a79adcd0b6a593e4a9?pvs=21)

[SDT-CCM Communication Workflow](https://www.notion.so/SDT-CCM-Communication-Workflow-1775966d1a75804fb4a1db2194148854?pvs=21)

[Deliverable ToC](https://www.notion.so/Deliverable-ToC-1a75966d1a7580c09a0dcfbc5ee35932?pvs=21)

[COBALT CERTIFICATION SCHEME](https://www.notion.so/COBALT-CERTIFICATION-SCHEME-1ae5966d1a7580ef8ebbf2063c3ba692?pvs=21)

[COBALT WORKFLOWS](https://www.notion.so/COBALT-WORKFLOWS-1ae5966d1a758067bc35d967d040aae2?pvs=21)

# Useful Impementation Links

| IBM CBOM Kit Viewer | [https://www.zurich.ibm.com/cbom/](https://www.zurich.ibm.com/cbom/) |
| --- | --- |
| IBM CBOM SonarQube Plugin  | [https://github.com/IBM/sonar-cryptography](https://github.com/IBM/sonar-cryptography) |
| IBM CBOM | https://github.com/IBM/cbomkit |
| CycloneDx documentation	
OWASP 	
 | [https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties_algorithmProperties_classicalSecurityLevel](https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties_algorithmProperties_classicalSecurityLevel) |
| CycloneDX CBOM Book | [https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf) |
| NIST Final PQCI Standards	
 | [https://utimaco.com/news/blog-posts/nists-final-pqc-standards-are-here-what-you-need-know](https://utimaco.com/news/blog-posts/nists-final-pqc-standards-are-here-what-you-need-know) |
| NIST Post  Quantum Cryptography	 | [https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization) |

**COBALT GA**

T2.2 Status

Support of SBOM + VEX for Projects: Python, Java, PHP. Javascripts

Support of BOM-Links for currently implemented BOM files

Support of CBOM (Host Level): CBOM - Cryptographic Algorithms, Certificates, Protocols (+ Cryptographic Suites)

T2.2 Next Actions

Support of MLBOM and SaSBOM

Support of CBOM in Software (Code) Level

Modify OSCAL for the RISK Assessment Process

Meeting with UPC to conclude on endpoint and integration with NDT Manager

[Chania - DTaaS Conference Paper (1)](https://www.notion.so/Chania-DTaaS-Conference-Paper-1-1a65966d1a758085b5f9e6c2569e2308?pvs=21)

[vulners with nmap](https://www.notion.so/vulners-with-nmap-1a45966d1a75808ab263da34e7123a5e?pvs=21)

1 ToE Management Interface

Description: Allows manufacturers or developers to register and manage the Target of Evaluation (ToE) within COBALT.

Endpoints: 

POST /toe/register{id} → Register
GET /toe/{id} → Retrieve ToE details
PUT /toe/{id} → Update ToE information

2 Security Digital Twin (SDT) Interface

Description: Enables the creation and management of the Security Digital Twin, representing the digital counterpart of the ToE.

Endpoints:

POST /sdt/create → Create SDT based on ToE metadata
GET /sdt/{id} → Retrieve SDT details
PUT /sdt/{id} → Update SDT configuration

3 Evidence Collection Interface

Description: Manages the deployment and communication of Evidence Collectors that gather compliance data from the ToE.

Endpoint:

POST /evidence-collectors/deploy → Deploy evidence collectors to SDT
GET /evidence-collectors/{id} → Retrieve collected evidence
POST /evidence-collectors/report → Send collected evidence to Orchestrator

4 Orchestrator Communication Interface

Description: Facilitates coordination between components and manages workflow execution.

Endpoint:

POST /orchestrator/initiate-workflow → Start a workflow (WF1, WF2, or WF3)
GET /orchestrator/status/{workflowId} → Get status of a running workflow
POST /orchestrator/execute-step → Execute a specific step within a workflow

5 Risk Assessment Interface

Description: Sends collected evidence to the **Dynamic Risk Assessment (DRA) Tool** for computing risk scores.

Endpoint:

POST /risk-assessment/compute → Submit evidence for risk computation
GET /risk-assessment/result/{toeId} → Retrieve computed risk score

6 Certificate Management Interface

Description: Handles certificate issuance, updates, renewals, suspensions, and withdrawals.
Endpoints:

POST /certificate/create → Create a new certificate
PUT /certificate/update/{id} → Update certificate details
GET /certificate/status/{id} → Get current certificate status
DELETE /certificate/withdraw/{id} → Withdraw a certificate

7 Decision Engine Interface

Description: Manages decision-making based on risk assessment results and predefined policies.

Endpoints:

POST /decision-engine/evaluate → Evaluate computed risk and determine certificate status
GET /decision-engine/actions/{toeId} → Retrieve recommended mitigation actions

8 Compliance Ledger Interface

Description: Ensures tamper-proof storage of security specifications, assessments, and certification decisions.

Endpoints:

POST /ledger/store → Store security evidence and compliance decisions
GET /ledger/retrieve/{id} → Retrieve stored compliance records

9 External Risk Data Interface

Description: Integrates with external sources for security threat intelligence (e.g., vulnerability databases).

Endpoints:

GET /external-risk/vulnerabilities → Fetch latest vulnerabilities for the ToE
GET /external-risk/threats → Retrieve ongoing cybersecurity threats