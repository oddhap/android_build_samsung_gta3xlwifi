
import com.android.server.permission.PermissionBpfMap
import android.util.SparseIntArray
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.Collections
import kotlin.concurrent.thread
fun <T> List<T>.allIndexed(predicate:(Int,T)->Boolean):Boolean {for(i in indices)if(!predicate(i,this[i]))return false;return true}
typealias ArrayMap<K,V> = java.util.LinkedHashMap<K,V>
class MutableIntSet { private val data=linkedSetOf<Int>();val size get()=data.size;operator fun plusAssign(v:Int){data.add(v)};fun forEachIndexed(block:(Int,Int)->Unit){data.forEachIndexed(block)} }
object UserHandle { fun getUid(user:Int,app:Int)=user*100000+app }
class Users(val ids:List<Int>){val size get()=ids.size;fun forEachIndexed(block:(Int,Int,Unit)->Unit){ids.forEachIndexed{i,u->block(i,u,Unit)}}}
data class UserPackage(val isInstalled:Boolean)
class PackageState(val appId:Int,val isApex:Boolean,val installed:Set<Int>){fun getUserStateOrDefault(id:Int)=UserPackage(id in installed)}
class External(val packageStates:Map<String,PackageState>)
data class State(val raw:Int,val userStates:Users,val externalState:External)
class Scope(val state:State)
class AccessCheckingService(@Volatile var state:State){
 private val stateLock=Any()
internal fun <T> withPermissionStateLock(action: () -> T): T =
        synchronized(stateLock) { action() }
 fun <T> getState(action:Scope.()->T)=Scope(state).action()
 fun mutate(raw:Int,callback:(State)->Unit){synchronized(stateLock){state=state.copy(raw=raw);callback(state)}}
}
class PermissionService(val service:AccessCheckingService,val ordered:Boolean){
 val bpfMapPermissionNamesLock=Any()
 @Volatile var bpfMapPermissionNames=ArrayMap<PermissionBpfMap,List<String>>()
 val MAX_ALLOWED_BPF_PERMISSIONS=32
 val ALLOWED_BPF_PERMISSIONS=(0..9).map{"P$it"}.toSet()
 var snapshotHook:(()->Unit)?=null
 fun getBpfMapUidsPermissionBits(names:List<String>):SparseIntArray{val bits=service.getState {SparseIntArray().apply {if(state.raw!=0)put(10001,state.raw);state.userStates.ids.forEach{put(UserHandle.getUid(it,0),(1 shl names.size)-1);put(UserHandle.getUid(it,1000),(1 shl names.size)-1)}}};snapshotHook?.invoke();return bits}
fun registerNew(bpfMap: PermissionBpfMap, permissionNames: List<String>) {
        require(permissionNames.isNotEmpty()) { "permissionNames cannot be empty" }
        require(permissionNames.size <= MAX_ALLOWED_BPF_PERMISSIONS) {
            "Too many permissions, max of $MAX_ALLOWED_BPF_PERMISSIONS allowed, provided " +
                "${permissionNames.size}"
        }
        require(
            permissionNames.allIndexed { _, permissionName ->
                permissionName in ALLOWED_BPF_PERMISSIONS
            }
        ) {
            "Permission ${permissionNames.first { it !in ALLOWED_BPF_PERMISSIONS }} is not " +
                "allowed for BPF map registration"
        }

        service.withPermissionStateLock {
            synchronized(bpfMapPermissionNamesLock) {
                require(bpfMap !in bpfMapPermissionNames) { "BPF map already registered" }
                bpfMapPermissionNames =
                    ArrayMap(bpfMapPermissionNames).apply { this[bpfMap] = permissionNames }
            }
            try {
                // The same lock protects mutation publication and its synchronous
                // callbacks. A newer revocation cannot precede an older initial
                // snapshot and then be overwritten by it.
                val uidsPermissionBits = getBpfMapUidsPermissionBits(permissionNames)
                service.getState {
                    val userIds = IntArray(state.userStates.size)
                    val knownUids = MutableIntSet()
                    state.userStates.forEachIndexed { index, userId, _ ->
                        userIds[index] = userId
                        state.externalState.packageStates.forEach { (_, packageState) ->
                            if (!packageState.isApex &&
                                packageState.getUserStateOrDefault(userId).isInstalled) {
                                knownUids += UserHandle.getUid(userId, packageState.appId)
                            }
                        }
                    }
                    val knownPackageUids = IntArray(knownUids.size)
                    knownUids.forEachIndexed { index, uid -> knownPackageUids[index] = uid }
                    bpfMap.setInitialUidPermissions(userIds, knownPackageUids, uidsPermissionBits)
                }
            } catch (failure: Throwable) {
                synchronized(bpfMapPermissionNamesLock) {
                    bpfMapPermissionNames =
                        ArrayMap(bpfMapPermissionNames).apply { this -= bpfMap }
                }
                throw failure
            }
        }
    }
fun registerOld(bpfMap: PermissionBpfMap, permissionNames: List<String>) {
        require(permissionNames.isNotEmpty()) { "permissionNames cannot be empty" }
        require(permissionNames.size <= MAX_ALLOWED_BPF_PERMISSIONS) {
            "Too many permissions, max of $MAX_ALLOWED_BPF_PERMISSIONS allowed, provided " +
                "${permissionNames.size}"
        }
        require(bpfMap !in bpfMapPermissionNames) { "BPF map already registered" }
        require(
            permissionNames.allIndexed { _, permissionName ->
                permissionName in ALLOWED_BPF_PERMISSIONS
            }
        ) {
            "Permission ${permissionNames.first { it !in ALLOWED_BPF_PERMISSIONS }} is not " +
                "allowed for BPF map registration"
        }

        synchronized(bpfMapPermissionNamesLock) {
            bpfMapPermissionNames =
                ArrayMap(bpfMapPermissionNames).apply { this[bpfMap] = permissionNames }
        }
        val uidsPermissionBits = getBpfMapUidsPermissionBits(permissionNames)
        bpfMap.setUidsPermissionBits(uidsPermissionBits)
    }
 fun register(map:PermissionBpfMap,names:List<String>){if(ordered)registerNew(map,names)else registerOld(map,names)}
 fun mutate(raw:Int){service.mutate(raw){s->val bits=SparseIntArray();bits.put(10001,s.raw);bpfMapPermissionNames.keys.forEach{it.setUidsPermissionBits(bits)}}}
}
class Receiver:PermissionBpfMap{
 val values=Collections.synchronizedList(mutableListOf<Int>())
 var users:IntArray?=null;var known:IntArray?=null;var fail=false
 override fun setUidsPermissionBits(bits:SparseIntArray){if(fail)error("callback failed");values.add(bits.get(10001))}
 override fun setInitialUidPermissions(u:IntArray,k:IntArray,bits:SparseIntArray){users=u;known=k;setUidsPermissionBits(bits)}
 override fun removeAppId(id:Int){};override fun removeUser(id:Int){}
}
class OldReceiver:PermissionBpfMap{var calls=0;var bits:SparseIntArray?=null;override fun setUidsPermissionBits(b:SparseIntArray){calls++;bits=b};override fun removeAppId(id:Int){};override fun removeUser(id:Int){}}
fun fixture(ordered:Boolean):PermissionService{val pkgs=linkedMapOf("a" to PackageState(10001,false,setOf(0,10)),"shared" to PackageState(10001,false,setOf(0,10)),"no-perm" to PackageState(10002,false,setOf(0)),"other-user" to PackageState(10003,false,setOf(10)),"apex" to PackageState(11000,true,setOf(0,10)));return PermissionService(AccessCheckingService(State(4,Users(listOf(0,10)),External(pkgs))),ordered)}
val names=(0..9).map{"P$it"}
fun await(l:CountDownLatch){check(l.await(10,TimeUnit.SECONDS))}
fun main(){var cases=0
 // Pin the old registration bug deterministically: newer revoke, then old grant.
 run{val p=fixture(false);val receiver=Receiver();val captured=CountDownLatch(1);val release=CountDownLatch(1);p.snapshotHook={captured.countDown();await(release)};val reader=thread{p.register(receiver,names)};await(captured);p.mutate(0);release.countDown();reader.join();check(receiver.values==listOf(0,4));cases++}
 repeat(50){val p=fixture(true);val receiver=Receiver();val captured=CountDownLatch(1);val release=CountDownLatch(1);val attempting=CountDownLatch(1);p.snapshotHook={captured.countDown();await(release)};val reader=thread{p.register(receiver,names)};await(captured);val writer=thread{attempting.countDown();p.mutate(0)};await(attempting);check(receiver.values.isEmpty());release.countDown();reader.join();writer.join();check(receiver.values==listOf(4,0));check(receiver.users!!.toSet()==setOf(0,10));check(receiver.known!!.toSet()==setOf(10001,10002,1010001,1010003));check(receiver.known!!.size==4);cases++}
 run{val p=fixture(true);val old=OldReceiver();p.register(old,names);check(old.calls==1&&old.bits!!.get(10001)==4&&old.bits!!.get(0)==1023&&old.bits!!.get(1000)==1023&&old.bits!!.get(1000000)==1023&&old.bits!!.get(1001000)==1023);p.mutate(0);check(old.calls==2&&old.bits!!.get(10001)==0);cases++}
 run{val p=fixture(true);val receiver=Receiver();receiver.fail=true;check(runCatching{p.register(receiver,names)}.isFailure);check(p.bpfMapPermissionNames.isEmpty());receiver.fail=false;p.mutate(0);check(receiver.values.isEmpty());p.register(receiver,names);check(receiver.values==listOf(0));cases++}
 repeat(25){val p=fixture(true);val receiver=Receiver();val successes=AtomicInteger();val failures=AtomicInteger();val start=CountDownLatch(1);val work={await(start);try{p.register(receiver,names);successes.incrementAndGet()}catch(expected:IllegalArgumentException){failures.incrementAndGet()};Unit};val a=thread(block=work);val b=thread(block=work);start.countDown();a.join();b.join();check(successes.get()==1&&failures.get()==1&&receiver.values==listOf(4));cases++}
 for(bad in listOf(emptyList(),listOf("unknown"),List(33){"P0"})){val p=fixture(true);check(runCatching{p.register(Receiver(),bad)}.isFailure&&p.bpfMapPermissionNames.isEmpty());cases++}
 println("passed_cases=$cases ordered_races=50 duplicate_races=25 old_race_reproduced=true")
}
