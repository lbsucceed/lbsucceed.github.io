+++
title = "English Resume"
description = "Curriculum Vitae for Bo Liu"
template = "resume.html"

[extra]
lang = "en"
name = "Bo Liu"
role = "Machine Learning Engineer"
summary = """
Focused on building practical machine learning systems for computer vision and applied security. I enjoy translating research into real products, optimizing performance, and keeping the operational stack simple enough to maintain.
"""
footer = "Last updated in 2025 · Built with Zola and Serene"

[[extra.contact]]
label = "Location"
value = "Shanghai, China"

[[extra.contact]]
label = "Email"
value = "woaikanpika123@gmail.com"
url = "mailto:woaikanpika123@gmail.com"

[[extra.contact]]
label = "GitHub"
value = "github.com/lbsucceed"
url = "https://github.com/lbsucceed"

[[extra.contact]]
label = "LinkedIn"
value = "linkedin.com/in/boliu"
url = "https://www.linkedin.com/in/boliu"

[[extra.skills]]
name = "Programming"
items = ["Python", "C++", "Rust", "Go"]

[[extra.skills]]
name = "Machine Learning"
items = ["PyTorch", "ONNX Runtime", "TensorRT", "OpenCV"]

[[extra.skills]]
name = "Ops Tooling"
items = ["Docker", "GitHub Actions", "Grafana", "Prometheus"]

[[extra.experience]]
role = "Senior Machine Learning Engineer"
company = "Acme Vision Lab"
period = "2023 - Present"
location = "Shanghai, China"
summary = "Lead engineer for real time perception on embedded devices."
highlights = [
  "Reduced inference latency by 37% through model distillation and quantization.",
  "Deployed CI driven evaluation harness that catches regression within 30 minutes.",
  "Partnered with product teams to ship three customer facing releases on schedule."
]

[[extra.experience]]
role = "Software Engineer"
company = "Northlight Security"
period = "2020 - 2023"
location = "Beijing, China"
summary = "Built detection pipelines and automation for the incident response platform."
highlights = [
  "Designed stream processing jobs that scale to billions of events each day.",
  "Owned the rollout of zero downtime upgrade process across four regions.",
  "Mentored junior engineers and set coding guidelines that cut review churn."
]

[[extra.projects]]
name = "CV Inference Toolkit"
tagline = "Open source acceleration utilities"
period = "2024"
link = "https://github.com/lbsucceed/cv-infer-toolkit"
link_label = "Repository"
summary = "Tooling and documentation that streamline packaging, profiling, and benchmarking for computer vision workloads."
highlights = [
  "Unified profiling reports across TensorRT, ONNX Runtime, and OpenVINO.",
  "Packaged reusable GitHub Actions that publish ready to test Docker images."
]

[[extra.projects]]
name = "ThreatLab Dashboard"
tagline = "Operational visibility"
period = "2022"
summary = "Grafana dashboards and alert rules that visualize real time telemetry while keeping operators focused on priority incidents."
highlights = [
  "Integrated anomaly detection with less than 2% false positive rate.",
  "Delivered live runbooks that reduce mean time to recovery by 40%."
]

[[extra.education]]
degree = "M.S. Computer Science"
institution = "Tsinghua University"
period = "2018 - 2020"
location = "Beijing, China"
details = "Research focus on distributed inference for large scale vision workloads."

[[extra.education]]
degree = "B.S. Information Security"
institution = "Shanghai Jiao Tong University"
period = "2014 - 2018"
location = "Shanghai, China"
+++
