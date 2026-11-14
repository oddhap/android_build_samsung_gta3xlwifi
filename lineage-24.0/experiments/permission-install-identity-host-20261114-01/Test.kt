
object PermissionManagerServiceInternal { class PackageInstalledParams {companion object {val DEFAULT=PackageInstalledParams()}} }
class External(var packages:Map<String,Int>,var disabled:Map<String,Int>,var known:Map<String,Int>){fun setPackageStates(value:Map<String,Int>){packages=value};fun setDisabledSystemPackageStates(value:Map<String,Int>){disabled=value};fun setKnownPackages(value:Map<String,Int>){known=value};fun copy()=External(packages,disabled,known)}
class State(val external:External,val flags:Map<String,Int>){fun mutateExternalState()=external}
class Scope(val newState:State)
class PM(var installed:Map<String,Int>,var disabled:Map<String,Int>){var calls=0;var fail=false;var verify:()->Unit={};val allPackageStates:Pair<Map<String,Int>,Map<String,Int>> get(){verify();calls++;if(fail)error("snapshot failure");return Pair(installed,disabled)}}
class Internal(var known:Map<String,Int>){var calls=0;var fail=false;var verify:()->Unit={};val knownPackages:Map<String,Int> get(){verify();calls++;if(fail)error("known failure");return known}}
class AccessCheckingService{
 private lateinit var state:State
 private lateinit var packageManagerLocal:PM
 private lateinit var packageManagerInternal:Internal
 private val stateLock=Any()
 var inMutation=false;var mutations=0;var notifications=0
 var observer:(State)->Unit={}
 fun initialize(s:State,p:PM,i:Internal){state=s;packageManagerLocal=p;packageManagerInternal=i;p.verify={check(!inMutation)};i.verify={check(!inMutation)}}
 fun value()=state
 fun mutateState(action:Scope.()->Unit){synchronized(stateLock){inMutation=true;val next=State(state.external.copy(),state.flags);try{Scope(next).action();state=next;mutations++;notifications++;observer(next)}finally{inMutation=false}}}
internal fun refreshPackageIdentityStateIfInitialized() {
        if (!::state.isInitialized) return
        // Match the existing package callbacks: never query PackageManager while
        // holding the permission-state lock (PackageManager also calls into us).
        val (packageStates, disabledSystemPackageStates) = packageManagerLocal.allPackageStates
        val knownPackages = packageManagerInternal.knownPackages
        mutateState {
            newState.mutateExternalState().apply {
                setPackageStates(packageStates)
                setDisabledSystemPackageStates(disabledSystemPackageStates)
                setKnownPackages(knownPackages)
            }
        }
    }
}
class PermissionService(val service:AccessCheckingService){var oldPolicyCalls=0;fun onPackageInstalled(params:PermissionManagerServiceInternal.PackageInstalledParams){
if (params === PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT) {
            // TODO: We should actually stop calling onPackageInstalled() when we are passing
            //  PackageInstalledParams.DEFAULT in InstallPackageHelper, because there's actually no
            //  installer in those cases of system app installs, and the default params won't
            //  allowlist any permissions which means the original UPGRADE_EXEMPT will be dropped
            //  without any INSTALLER_EXEMPT added. However, we can't do that right now because the
            //  old permission subsystem still depends on this method being called to set up the
            //  permission state for the first time (which we are doing in onPackageAdded() or
            //  onStorageVolumeMounted() now).
            service.refreshPackageIdentityStateIfInitialized()
            return
        }
 oldPolicyCalls++
}}
fun main(){var cases=0
 fun pass(value:Boolean){check(value);cases++}
 val cold=AccessCheckingService();val wrapper=PermissionService(cold)
 wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT);pass(cold.mutations==0&&wrapper.oldPolicyCalls==0)
 wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams());pass(cold.mutations==0&&wrapper.oldPolicyCalls==1)
 val originalFlags=mapOf("UPGRADE_EXEMPT" to 1,"INTERNET" to 4,"NO_PERMISSIONS" to 0)
 val initial=State(External(mapOf("old" to 10001),emptyMap(),mapOf("role" to 10001)),originalFlags)
 val pm=PM(mapOf("new-zero" to 10002,"shared-a" to 10001,"shared-b" to 10001),mapOf("disabled" to 11000));val internal=Internal(mapOf("role" to 10001))
 cold.initialize(initial,pm,internal);var observed:State?=null;cold.observer={observed=it}
 wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)
 pass(cold.mutations==1&&cold.notifications==1&&pm.calls==1&&internal.calls==1)
 pass(cold.value().external.packages==pm.installed&&cold.value().external.disabled==pm.disabled&&cold.value().external.known==internal.known)
 pass(cold.value().flags===originalFlags&&cold.value().flags["UPGRADE_EXEMPT"]==1&&cold.value().flags["NO_PERMISSIONS"]==0)
 pass(observed===cold.value()&&observed!!.external.packages["new-zero"]==10002)
 pass(initial.external.packages==mapOf("old" to 10001)&&wrapper.oldPolicyCalls==1)
 // A later DEFAULT install gets current identity with unchanged permission-policy flags.
 pm.installed=mapOf("next-zero" to 10003);internal.known=emptyMap();wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)
 pass(cold.mutations==2&&cold.value().external.packages==mapOf("next-zero" to 10003)&&cold.value().flags===originalFlags)
 // Failed external reads cannot publish state or notify a fictitious complete snapshot.
 val before=cold.value();pm.fail=true;pass(runCatching{wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)}.isFailure);pass(cold.value()===before&&cold.mutations==2&&cold.notifications==2)
 pm.fail=false;internal.fail=true;pass(runCatching{wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT)}.isFailure);pass(cold.value()===before&&cold.mutations==2&&cold.notifications==2)
 internal.fail=false;wrapper.onPackageInstalled(PermissionManagerServiceInternal.PackageInstalledParams.DEFAULT);pass(cold.mutations==3&&cold.notifications==3&&cold.value().flags===originalFlags)
 println("passed_cases=$cases")
}
