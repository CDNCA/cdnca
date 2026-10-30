REVOKE SELECT,INSERT,UPDATE,DELETE ON TABLE
    cc_reference_matchers,cc_reference_filters,cc_reference_versions,cc_reference_write_requests
    FROM cdnca_control_app;
DROP TABLE cc_reference_write_requests;
DROP TABLE cc_reference_versions;
DROP TABLE cc_reference_filters;
DROP TABLE cc_reference_matchers;
