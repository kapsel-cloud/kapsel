//! Exact static installation records for the KAP-0074 resident preview.

#[test]
fn unit_sysusers_and_rbac_records_are_exact_and_finite() {
    assert_eq!(
        include_str!("../deploy/kapseld.service"),
        concat!(
            "[Unit]\n",
            "Description=Kapsel resident preview\n",
            "StartLimitIntervalSec=0\n",
            "\n",
            "[Service]\n",
            "Type=exec\n",
            "User=kapsel\n",
            "Group=kapsel-preview-callers\n",
            "RuntimeDirectory=kapsel\n",
            "RuntimeDirectoryMode=0750\n",
            "StateDirectory=kapsel\n",
            "StateDirectoryMode=0700\n",
            "UMask=0077\n",
            "ExecStart=/usr/libexec/kapsel/kapseld --operator-config ",
            "/etc/kapsel/operator.json --socket /run/kapsel/kapseld.sock\n",
            "Restart=no\n",
            "StandardOutput=null\n",
            "StandardError=null\n",
            "\n",
            "[Install]\n",
            "WantedBy=multi-user.target\n",
        )
    );
    assert_eq!(
        include_str!("../deploy/kapseld.conf"),
        concat!(
            "g kapsel-preview-callers - -\n",
            "u kapsel - \"Kapsel preview service\" /var/lib/kapsel /usr/sbin/nologin\n",
        )
    );
    assert_eq!(
        include_str!("../deploy/kapseld-rbac.yaml"),
        concat!(
            "apiVersion: v1\n",
            "kind: ServiceAccount\n",
            "metadata:\n",
            "  name: kapsel-preview\n",
            "  namespace: demo\n",
            "automountServiceAccountToken: false\n",
            "---\n",
            "apiVersion: rbac.authorization.k8s.io/v1\n",
            "kind: Role\n",
            "metadata:\n",
            "  name: kapsel-preview-agent-api\n",
            "  namespace: demo\n",
            "rules:\n",
            "  - apiGroups: [\"apps\"]\n",
            "    resources: [\"deployments\"]\n",
            "    resourceNames: [\"agent-api\"]\n",
            "    verbs: [\"get\", \"patch\"]\n",
            "---\n",
            "apiVersion: rbac.authorization.k8s.io/v1\n",
            "kind: RoleBinding\n",
            "metadata:\n",
            "  name: kapsel-preview-agent-api\n",
            "  namespace: demo\n",
            "subjects:\n",
            "  - kind: ServiceAccount\n",
            "    name: kapsel-preview\n",
            "    namespace: demo\n",
            "roleRef:\n",
            "  apiGroup: rbac.authorization.k8s.io\n",
            "  kind: Role\n",
            "  name: kapsel-preview-agent-api\n",
        )
    );
}
