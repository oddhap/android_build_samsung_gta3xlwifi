# Historical socket table build attempt

This first isolated delta passed52 host assertions/864 grammar comparisons but
full GCC kernel compilation failed because ip_hdrlen requires net/ip.h. Full
before/after/protected/Android source audits were retained. No production input
was changed. kernel-socket-tables-20261108-02 supersedes this attempt with the
explicit include and a fresh source/output directory; do not promote this input.
