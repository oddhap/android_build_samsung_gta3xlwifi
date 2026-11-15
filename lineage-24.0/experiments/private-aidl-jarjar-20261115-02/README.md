# Preserve native Binder identity through actual A17 jarjar

Actual original service rules rename all three private/native OEM interfaces and
rewrite their Java DESCRIPTOR values to android.net.connectivity.com.android...
while native netd retains com.android.internal.net.... This breaks Binder identity.

The inactive fragment adds only IGta3xlwifiNetpolicy, IOemNetd and
IOemNetdUnsolicitedEventListener, including nested classes, to the existing service
jarjar excludes. Original initializer exclusions are retained verbatim.

The tool replays the complete15-source SDK compile using the real original Soong
Android core modules, runs the pinned actual A17 gen_jarjar.py and jarjar.jar on
the freshly compiled classes, and inspects real post-transform class fields with
JDK javap. Original rules demonstrate all three mismatches; the fixed rules retain
all three native descriptors, original/nested class names and all16 transaction
ordinals. Actual generated native C++ descriptors are bound as the oracle.
1243 projects/17 exact source patches pass audits before/after. No Android Binder
execution, selected source change or complete Soong/APEX validation is claimed.

Attempt01 looked for the unchanged unsolicited native source in the newly staged
output;02 binds its actual existing Soong-generated source instead. No descriptor
or native source was altered to satisfy the check. Final composition must include
this fragment and the new Java AIDL module (system_server_current,min31,tethering
APEX), actual sources/headers/dependencies and native callback/export integration.
No flash-ready ROM exists.
