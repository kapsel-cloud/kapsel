//! Concrete Kubernetes behavior and bounded receiver facts.

pub(in crate::gateway) mod adapter;
pub(in crate::gateway) mod facts;

pub(crate) use adapter::KubernetesDeploymentImageAdapter;
pub(crate) use facts::{ApplyOutcome, ReceiverObservation, TargetIdentity};
