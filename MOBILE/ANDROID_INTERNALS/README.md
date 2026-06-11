# Android Internals 

---

## Table of Contents

1. [Android Architecture — The Stack](#1-android-architecture--the-stack)
2. [Inter-Process Communication (IPC)](#2-inter-process-communication-ipc)
3. [Binder — The Heart of Android](#3-binder--the-heart-of-android)
4. [Android Framework & Apps](#4-android-framework--apps)
5. [Android Security Model](#5-android-security-model)
6. [Application Sandboxing](#6-application-sandboxing)
7. [Permissions System](#7-permissions-system)
8. [Zygote & Process Model](#8-zygote--process-model)
9. [JVM vs Dalvik vs ART](#9-jvm-vs-dalvik-vs-art)
10. [Code Signing](#10-code-signing)
11. [Package Management Internals](#11-package-management-internals)
12. [APK Install Process](#12-apk-install-process)
13. [Package Updates](#13-package-updates)
14. [Encrypted APKs & Forward Locking](#14-encrypted-apks--forward-locking)
15. [Package Verification](#15-package-verification)

---

## 1. Android Architecture — The Stack

```
┌─────────────────────────────────────┐
│           APPS (Layer 5)            │  ← What users touch
├─────────────────────────────────────┤
│        FRAMEWORK (Layer 4)          │  ← Developer toolbox
├─────────────────────────────────────┤
│      SYSTEM SERVICES (Layer 3)      │  ← Engine room (daemons)
├─────────────────────────────────────┤
│         BINDER/IPC (Layer 2)        │  ← The messenger
├─────────────────────────────────────┤
│       LINUX KERNEL (Layer 1)        │  ← Foundation
└─────────────────────────────────────┘
```

Each layer only uses the layer directly below it. Apps never touch the kernel directly.

### Key Insight for VAPT
- Every layer is an attack surface
- Weaknesses in lower layers affect everything above
- Most app vulns are at Layer 4 & 5
- Most escalation vulns are at Layer 1 & 2

---

## 2. Inter-Process Communication (IPC)

### Why IPC Exists
```
Rule: Every app lives in its own memory bubble
      App A CANNOT read App B's memory
      App B CANNOT read App A's memory

Problem: Apps need to talk (Gmail ↔ Contacts, Maps ↔ GPS)
Solution: IPC — a controlled channel to communicate
```

### Old IPC Methods (Linux)
| Method | Problem |
|--------|---------|
| Files | Slow, messy, no real-time |
| Sockets | Too basic, no identity |
| Shared Memory | Dangerous, no isolation |
| Semaphores | Android killed support for System V IPCs |
| Pipes | Limited, one-direction |

**Android said:** None of these are good enough → built **Binder**

### The Restaurant Analogy
```
You (App A)      Waiter (Binder/Kernel)     Kitchen (App B)
    │                      │                      │
    │── "I want pizza" ───>│                      │
    │                      │── delivers order ───>│
    │                      │<── pizza ready ───── │
    │<── "here's pizza" ───│                      │
```

---

## 3. Binder — The Heart of Android

### What is Binder?
A kernel-level IPC mechanism. Every single cross-process call in Android goes through it. No exceptions.

```
/dev/binder = the post office of Android
```

### How Binder Works (Exact Flow)

```
Step 1: App A calls transact()
        Packages: [WHO to send to] [WHAT to do] [DATA]

Step 2: ONE ioctl() call to /dev/binder
        Kernel takes control

Step 3: Kernel copies message DIRECTLY into App B's memory
        (NOT two copies — one copy only, via kernel-managed memory chunk)

Step 4: Kernel taps App B (like a doorbell)
        "Hey, you have a message"

Step 5: App B reads from ITS OWN memory
        No memory violation — it's already in App B's space

Step 6: App B processes, sends response SAME WAY back

Step 7: Kernel frees the memory
        BC_FREE_BUFFER command
```

### The Memory Architecture
```
Process A memory:  [your code][your data][BINDER ZONE ← read only]
                                               ↑
                                    Kernel WRITES here directly
                                    from Process A's message

Process B memory:  [your code][your data][BINDER ZONE ← read only]
                                               ↑
                                    Process B reads from
                                    ITS OWN memory
                                    Zero violation ✅
```

**Why one copy?** Kernel manages a chunk of each process's memory directly. It writes from sender into receiver's chunk. No intermediate copy needed. Zero double-copy overhead.

### Binder Security — The Stamp System

Every Binder transaction contains:
```
Transaction Package:
├── Target object (who to call)
├── Method ID (what to do)
├── Data (parameters)
├── PID ← KERNEL stamps this. CANNOT be faked.
└── EUID ← KERNEL stamps this. CANNOT be faked.
```

**This prevents privilege escalation.** A malicious app cannot claim to be the system. The kernel stamps the real caller identity into every single transaction.

```java
// Receiver checks identity:
int callerUid = Binder.getCallingUid();
int callerPid = Binder.getCallingPid();
// These values are GUARANTEED by kernel — unfakeable
```

### Binder Objects & IBinder

```
IBinder interface = contract to receive Binder calls
Binder object    = anything implementing IBinder
Every system service = a Binder object

Two key methods:
transact()    ← caller uses this to SEND
onTransact()  ← receiver uses this to HANDLE
```

### Binder Identity — The Magic Property

If Process A creates a Binder object and passes it to B → B passes it to C:
```
Process A → holds real object (memory address 0xABCD)
Process B → holds handle (ticket #1) → kernel maps to 0xABCD
Process C → holds handle (ticket #2) → kernel maps to 0xABCD

ALL THREE point to the SAME object
Kernel maintains the mapping
```

**Consequences:**
- Cannot **fake** a Binder object
- Cannot **copy** a Binder object
- Only way to get one = someone gives it to you
- Makes Binder objects perfect security tokens

### Binder Tokens

A **Binder token** = a Binder object used as a capability/key.

```
Real world: Concert ticket
→ Show it = you get in
→ Cannot duplicate it
→ No name list needed

Binder token:
→ Possess it = you have access
→ Cannot forge it
→ No ACL needed
```

**Window tokens** (visible to developers):
```
Every app window → unique Binder token
Window Manager tracks all tokens
Want to add a window? → Must provide YOUR token
Can you get another app's token? → NO. Impossible.
```

### Capability-Based Security

```
Old way (ACL):                    Binder way (Capability):
Resource maintains list:          If you HAVE the token → access
├── App A → allowed               If you DON'T → no access
├── App B → denied                No lists. No lookups.
└── App C → allowed               Possession = permission
Problem: Lists get stale          Clean, simple, unforgeable
```

### Service Manager — The Phone Book

```
Boot time:
BluetoothService starts → registers with servicemanager
                          name: "bluetooth"
                          binder reference: [object]

Later, App A needs Bluetooth:
"Hey servicemanager, give me ref to 'bluetooth'"
servicemanager → hands over Binder reference
App A → talks directly to BluetoothService
```

**Security rule:** Only whitelisted system processes can REGISTER services. Example: only UID 1002 (AID_BLUETOOTH) can register "bluetooth".

Anyone can LOOK UP a service, but that doesn't guarantee they can USE it — the service itself checks identity.

### Other Binder Features

**Reference Counting:**
```
Someone uses Binder object → BC_INCREFS / BC_ACQUIRE (count ↑)
Someone is done           → BC_RELEASE / BC_DECREFS (count ↓)
Count hits zero           → object auto-freed
```

**Death Notification:**
```java
binderObject.linkToDeath(myCallback);
// If the service process dies → myCallback fires → you clean up
// Without this: your app hangs forever waiting for a dead service
```

### VAPT Relevance
```
Attack surfaces in Binder:
→ Exported Binder services without permission checks
→ Improper UID checking in onTransact()
→ Services accessible via service list command
→ Binder token theft/confusion
→ Intent-based Binder exploitation

Check:
$ adb shell service list
# Look for services without proper auth checks
```

---

## 4. Android Framework & Apps

### Framework = Developer Toolbox

Everything under `android.*` package:

| Package | What it gives |
|---------|--------------|
| `android.app.*` | Activities, Services, Providers |
| `android.view.*` | UI widgets, layouts |
| `android.widget.*` | Buttons, textviews |
| `android.database.*` | SQLite access |
| `android.content.*` | Files and data access |

### Managers = Facades Hiding Real Services

```
Your App
   ↓
BluetoothManager       ← you talk to this (facade/client)
   ↓
BluetoothManagerService ← actual daemon (hidden behind facade)
```

You never directly touch the daemon. The manager handles it.

### System Apps vs User Apps

**System Apps:**
```
Location:        /system/app/ or /system/priv-app/
Uninstallable?   NO
Trust level:     HIGH
Extra powers?    YES
Signed with:     Platform key
```

```
/system/app/      → normal system apps
/system/priv-app/ → PRIVILEGED system apps (even more powers)
                    Only these get signatureOrSystem permissions
```

**User Apps:**
```
Location:        /data/app/
Uninstallable?   YES
Trust level:     LOW
Extra powers?    NONE by default
Sandbox:         Strict — cannot affect other apps
```

### The 4 App Components

**Activity = One Screen**
```
What:     Single screen with UI
Key fact: Can be started by OTHER apps if exported
VAPT:     Exported activities = attack surface
```

**Service = Background Worker**
```
What:     Runs in background, no UI
Key fact: Can expose AIDL interface to other apps
VAPT:     Exported services = attack surface
          Unprotected bound services = privilege escalation
```

**Content Provider = Data Sharer**
```
What:     Interface to app's data (DB or files)
Key fact: Can expose data via IPC, fine-grained control
VAPT:     SQL injection via content URIs
          Path traversal in file providers
          Unauthenticated data access
```

**Broadcast Receiver = Event Listener**
```
What:     Listens for system or app broadcasts
Key fact: Can be targeted by other apps
VAPT:     Unprotected receivers = hijacking
          Intent injection
          Sticky broadcast manipulation
```

### AndroidManifest.xml — The App's ID Card

```xml
<manifest package="com.target.app">      ← unique ID
    <uses-permission android:name="..."/> ← what it asks for
    <application android:backup="true">  ← backup flag (VAPT: data extraction)
        <activity android:exported="true"/>  ← ATTACK SURFACE
        <service  android:exported="true"/>  ← ATTACK SURFACE
        <receiver android:exported="true"/>  ← ATTACK SURFACE
        <provider android:exported="true"/>  ← ATTACK SURFACE
    </application>
</manifest>
```

**For VAPT, always check:**
```bash
# Decompile APK
jadx-gui target.apk

# Check AndroidManifest.xml for:
# → exported="true" components
# → android:backup="true"
# → debuggable="true"
# → clearTextTrafficPermitted="true"
# → permissions declared vs used
```

---

## 5. Android Security Model

### Core Philosophy

Linux is a multi-user OS. Android twists this:
```
Traditional Linux:   UID = a physical human person
Android:             UID = an APP

Each app = a separate "user" in Linux terms
Kernel enforces isolation between UIDs
= apps isolated from each other at OS level
```

### The Security Layers

```
┌─────────────────────────────────────────────────────┐
│  VERIFIED BOOT     → system not tampered            │
│  SELinux           → mandatory policy, nobody bypass│
│  SANDBOXING        → each app = unique UID          │
│  PERMISSIONS       → apps must ask for extra power  │
│  BINDER            → unfakeable identity on IPC     │
│  CODE SIGNING      → updates verified by key        │
│  LINUX KERNEL      → foundation of everything       │
└─────────────────────────────────────────────────────┘
```

---

## 6. Application Sandboxing

### What Happens at Install Time

Android automatically does 3 things:
```
1. Assigns unique UID (e.g. 10037)
2. Creates dedicated process running as that UID
3. Creates private data directory owned by that UID
```

```bash
# Proof — real device process list:
$ ps
u0_a37  16973  ...  com.google.android.email    ← Gmail = UID u0_a37
u0_a8   18788  ...  com.google.android.dialer   ← Dialer = UID u0_a8
u0_a29  23128  ...  com.google.android.calendar ← Calendar = different UID
```

**Each app = different Linux user = total isolation**

### File System Isolation

```bash
# Gmail's private directory:
/data/data/com.google.android.email/
  drwxrwx--x  u0_a37  u0_a37  cache/
  drwxrwx--x  u0_a37  u0_a37  databases/
  drwxrwx--x  u0_a37  u0_a37  files/
  drwxrwx--x  u0_a37  u0_a37  shared_prefs/

# WhatsApp CANNOT read this → kernel blocks it
# Only u0_a37 (Gmail) and root can access
```

### UID Numbering Scheme

```
UID 0           → root (almost nothing runs as this)
UID 1000        → system (AID_SYSTEM) — special but limited
UID 1001-9999   → system daemons
  1001 = AID_PHONE      (telephony)
  1002 = AID_BLUETOOTH  (Bluetooth)
  1027 = AID_NFC        (NFC)
UID 10000+      → YOUR APPS start here
  10037 → u0_a37  (Gmail example)
  10089 → u0_a89  (WhatsApp example)
```

**Formula:**
```
UID 10037 → username: u0_a37
(10037 - 10000 = 37, so u0_a37)
```

### Packages Database

```bash
# Where UIDs are stored:
cat /data/system/packages.list

# Format:
# [package] [UID] [debuggable] [data_dir] [seinfo] [GIDs]
com.google.android.email  10037  0  /data/data/com.google.android.email  default  3003,1028,1015
#                                                                                   ↑ supplementary GIDs
#                                                              3003=INTERNET, 1028=SDCARD_R, 1015=SDCARD_RW
```

### Supplementary GIDs = Permission Implementation

```
Permission granted → GID assigned to process

INTERNET permission    → GID 3003 (AID_INET)
READ_EXTERNAL_STORAGE  → GID 1028 (AID_SDCARD_R)
WRITE_EXTERNAL_STORAGE → GID 1015 (AID_SDCARD_RW)
BLUETOOTH              → GID 1002 (AID_BLUETOOTH)

Zygote fork → child calls setgroups([3003, 1028, 1015])
Kernel checks GID → allows/denies network/storage access
Pure kernel enforcement — no Android code needed
```

### Shared User ID

Two apps sharing ONE Linux UID:
```xml
<manifest android:sharedUserId="android.uid.system">
```

Rules:
- Must be signed with SAME key
- Must plan from DAY ONE (cannot add later)
- Permission inheritance: App A has CAMERA, App B has MIC → both get both

Built-in shared UIDs:
```
android.uid.system    → 1000 (Settings, KeyChain)
android.uid.phone     → 1001 (Phone, Telephony)
android.uid.bluetooth → 1002 (Bluetooth)
android.uid.log       → 1007 (Log access)
android.uid.nfc       → 1027 (NFC)
```

### Multi-User Support

```
User 0 (device owner) → can manage everyone
User 1, 2, ...        → separate sandbox per user

Same app installed by two users:
→ Different effective UIDs
→ Different data directories
→ Completely separate sandboxes

Data:
/data/user/0/com.example.app/  ← User 0's data
/data/user/1/com.example.app/  ← User 1's data (separate)
App binaries: SHARED (saves space)
```

---

## 7. Permissions System

### The Permission Lifecycle

```
MOMENT 1 — Developer writes app:
    <uses-permission android:name="android.permission.CAMERA"/>

MOMENT 2 — User installs app:
    Android reads the list → grants or denies
    Once granted → stays granted forever
    (except development permissions)

MOMENT 3 — App runs:
    Android checks: does UID have the permission?
    YES → allow
    NO  → SecurityException
```

### Where System Permissions Are Born

All system permissions defined in ONE file:
```
/system/framework/framework-res.apk
    └── AndroidManifest.xml  ← birth certificate of all permissions
```

This APK:
- Has NO code (only resources + manifest)
- Signed with platform key
- Package name: `android`
- Shared UID: `android.uid.system` (1000)

### Protection Levels

```
normal          → low risk, auto-granted, user NOT asked
                  Example: VIBRATE, SET_WALLPAPER

dangerous       → high risk, user MUST approve (popup)
                  Example: CAMERA, CONTACTS, LOCATION, SMS

signature       → ONLY apps signed with SAME key as definer
                  Example: NET_ADMIN, MANAGE_BLUETOOTH
                  Third party apps: IMPOSSIBLE

signature|system → same key AND must be in /system partition
                  Example: MANAGE_USB

signature|system|development → above + shell/developer tools
                  Example: WRITE_SECURE_SETTINGS
                  Can be granted/revoked via ADB
```

### Platform Keys (4 Keys in Android)

```
platform key  → Signs: Settings, SystemUI, Phone, Bluetooth (core OS)
shared key    → Signs: Contacts, Search apps
media key     → Signs: Gallery, MediaProvider
testkey       → Signs: everything else in AOSP
               ⚠️ NEVER production use — public key!
```

**Why matters for VAPT:**
```
signature permission defined in framework-res.apk (platform key)
Your app must have platform key to get it
Third party: impossible
BUT: if testkey used in production build → anyone can sign malicious update
```

### Static vs Dynamic Enforcement

**Static (declarative):**
```xml
<activity android:permission="MY_PERMISSION"/>
<!-- Android auto-enforces. No code needed. -->
<!-- Like: a locked door — key required, automatic -->
```

**Dynamic (imperative):**
```java
public byte[] getStatistics() {
    // Check BEFORE doing anything
    mContext.enforceCallingPermission(
        android.Manifest.permission.BATTERY_STATS, null);
    // Only here if permission granted
    return data;
}
// Like: a bouncer INSIDE the club who checks again
```

### How Permission Check Works Internally

```java
// PackageManagerService.checkUidPermission():
public int checkUidPermission(String permName, int uid) {
    Object obj = mSettings.getUserIdLPr(UserHandle.getAppId(uid));
    if (obj != null) {
        GrantedPermissions gp = (GrantedPermissions)obj;
        if (gp.grantedPermissions.contains(permName)) {
            return PERMISSION_GRANTED;  // ✅
        }
    } else {
        // Check system-assigned permissions
        HashSet<String> perms = mSystemPermissions.get(uid);
        if (perms != null && perms.contains(permName)) {
            return PERMISSION_GRANTED;  // ✅
        }
    }
    return PERMISSION_DENIED;  // ❌
}
```

**Flow:**
```
Step 1: Is caller root (UID 0) or system (UID 1000)?
        → YES: auto-granted

Step 2: Is target component private (not exported)?
        → YES: BLOCKED regardless of permissions

Step 3: UID → Package → grantedPermissions set → contains permission?
        YES → GRANTED
        NO  → DENIED
```

### Permission Checks Per Component

**Activities & Services:**
```
startActivity()  → checked BEFORE starting
startService()   → checked BEFORE starting
stopService()    → checked BEFORE stopping
bindService()    → checked BEFORE binding
Fail: SecurityException immediately
```

**Content Providers (most granular):**
```xml
<provider
    android:readPermission="READ_CONTACTS"   ← controls query()
    android:writePermission="WRITE_CONTACTS" ← controls insert/update/delete
    <path-permission
        android:pathPattern="/contacts/.*/photo"
        android:readPermission="GLOBAL_SEARCH"/>  ← overrides global for this path
```

**Broadcasts (two-way):**
```java
// Sender restricts who can receive:
sendBroadcast(intent, "RECEIVER_MUST_HAVE_THIS");

// Receiver restricts who can send to it:
// <receiver android:permission="SENDER_MUST_HAVE_THIS"/>
```
- Both checks happen at delivery time
- Fail = receiver silently SKIPPED (no exception, no crash)

### Protected Broadcasts

```
Examples: BOOT_COMPLETED, PACKAGE_INSTALLED

Only these UIDs can send:
SYSTEM_UID, PHONE_UID, SHELL_UID, BLUETOOTH_UID, root

Anyone else sends → SecurityException immediately
```

### Custom Permissions

```xml
<!-- Define your own -->
<permission
    android:name="com.myapp.permission.DO_SOMETHING"
    android:protectionLevel="signature"/>

<!-- Protect your component -->
<activity android:permission="com.myapp.permission.DO_SOMETHING"/>

<!-- Other app requests it -->
<uses-permission android:name="com.myapp.permission.DO_SOMETHING"/>
```

**Critical rule:** Definer app must be installed FIRST. If unknown permission → silently ignored → never granted.

**"First one wins" vulnerability:**
```
App A defines: MY_PERM (signature level) — installs first
App B defines: MY_PERM (normal level)   — installs second (ignored)
Result: MY_PERM = signature level (App A wins) ✅

DANGEROUS REVERSE:
App B installs first (normal level registered)
App A installs second (signature level ignored)
Result: MY_PERM = normal level → ANY app gets it ❌
```

**VAPT check:** Always verify protection level of custom permissions matches expected level.

### Development Permissions

```bash
# Can be granted/revoked at runtime:
adb shell pm grant com.target.app android.permission.READ_LOGS
adb shell pm revoke com.target.app android.permission.READ_LOGS

# Only works as UID 2000 (ADB shell)
# Normal apps cannot do this
```

### Public vs Private Components

```
Default:
Activity          → PRIVATE
Service           → PRIVATE
Broadcast Receiver → PRIVATE
Content Provider  → PUBLIC (changed to PRIVATE in API 17+)

Make public:
android:exported="true"         → explicitly public
<intent-filter>...</intent-filter> → implicitly public

Keep private despite intent-filter:
<service android:exported="false">
    <intent-filter>...</intent-filter>  ← still private
</service>
```

**Private component = ultimate lock:**
```
External app tries to access private component
→ ActivityManager BLOCKS immediately
→ Doesn't matter what permissions caller has
→ Only exception: root (0) or system (1000)
```

### Dynamic URI Permissions

```java
// Grant temporary access to ONE specific URI
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setDataAndType(attachmentUri, "image/jpeg");
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
startActivity(intent);
// Access auto-revoked when receiving task ends
```

```java
// Persistent URI permission (Android 4.4+)
// Survives reboots, stored in /data/system/urigrants.xml
intent.addFlags(FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
contentResolver.takePersistableUriPermission(uri, FLAG_GRANT_READ_URI_PERMISSION);
```

### Pending Intents

A **frozen action** with creator's identity baked in:
```java
// Creator:
Intent i = new Intent(this, MyReceiver.class);
PendingIntent pi = PendingIntent.getBroadcast(this, 0, i, 0);
alarmManager.set(AlarmManager.RTC_WAKEUP, triggerTime, pi);
```

When triggered later:
- Your app might not be running
- System fires PendingIntent with YOUR UID/permissions
- Executes with YOUR identity

**VAPT danger:** Vague PendingIntents → intent hijacking
```java
// DANGEROUS — no component specified:
Intent i = new Intent("com.example.DO_SOMETHING");
// ANY app can intercept this

// SAFE — explicit component:
Intent i = new Intent(this, MyReceiver.class);
```

---

## 8. Zygote & Process Model

### The Problem Zygote Solves

```
Starting a fresh JVM/Dalvik for every app:
→ 2-3 seconds per app launch
→ Massive memory usage (each app loads framework separately)
→ Terrible user experience

Solution: Zygote
→ Pre-warm process with everything loaded
→ Fork it instantly for each new app
→ Milliseconds per app launch
```

### What is Zygote?

```
Boot time:
init starts Zygote process (as ROOT)
Zygote preloads ALL Android framework classes into memory
Zygote listens on Unix socket named "zygote"
Zygote sits idle, warmed up, ready

App launch:
Request sent to zygote socket
Zygote: fork()
Child process inherits ALL framework classes (already in memory)
Child specializes itself → becomes your app
```

### Specialization — The Exact Steps

```c
pid = fork();
if (pid == 0) {  // child process
    setgroups(gids)          // Step 1: Set supplementary GIDs (permissions)
    setrlimits(rlimits)      // Step 2: Set resource limits
    setresgid(gid, gid, gid) // Step 3: Set real+effective+saved group ID
    setresuid(uid, uid, uid) // Step 4: Set real+effective+saved user ID
    setCapabilities(...)     // Step 5: Fine-tune Linux capabilities
    set_sched_policy(...)    // Step 6: CPU scheduling priority
    setSELinuxContext(...)    // Step 7: SELinux domain
    enableDebugFeatures(...) // Step 8: Debug if requested
}
```

**Why this order matters:**
```
Child starts as ROOT (inherited from Zygote)
ROOT powers allow: setgroups(), setrlimits(), setresuid()

After setresuid(uid, uid, uid):
→ saved UID ≠ 0
→ CANNOT go back to root EVER
→ Window permanently closed

This is intentional:
Root used ONLY to set up the jail
Then locked inside the jail forever
```

### Copy-on-Write — The Memory Magic

```
After fork():
Zygote memory:    [Framework classes at address X]
Gmail fork:       [Framework classes at address X] ← SAME physical memory
Maps fork:        [Framework classes at address X] ← SAME physical memory
WhatsApp fork:    [Framework classes at address X] ← SAME physical memory

All apps share ONE copy of framework in RAM
No separate copy until someone WRITES to a page
Then kernel makes a private copy for just that process
```

**Result:**
- All apps share framework memory
- Zero duplication of framework classes
- Massive RAM savings
- Fast fork (no copying needed)

### Process Tree

```bash
$ ps
PID   PPID   USER    NAME
1     0      root    /init              ← grandfather
181   1      root    zygote             ← parent of ALL apps
1139  181    radio   com.android.phone  ← Phone app (child of zygote)
1154  181    nfc     com.android.nfc    ← NFC (child of zygote)
1219  181    u0_a7   com.google.gms     ← GMS (child of zygote)
```

### VAPT Relevance

```
Zygote socket = /dev/socket/zygote
Only accessible to system → but worth noting for escalation research

Debuggable flag (step 8):
If app is debuggable → attacker can attach debugger
→ Read memory
→ Manipulate execution
→ Extract secrets

Check:
adb shell run-as com.target.app  ← only works if debuggable
```

---

## 9. JVM vs Dalvik vs ART

### The Translation Journey

```
Java Code (.java)
      ↓ javac
.class files (Java bytecode — middle language)
      ↓ dx / d8 tool
classes.dex (Dalvik/Android bytecode — all classes ONE file)
      ↓ (install time)
.oat file (compiled machine code — ART creates this)
      ↓
CPU executes directly
```

### JVM (Not Used on Android)

```
JVM = translator that runs .class files
JRE = JVM + standard libraries

Built for desktop/server:
→ Lots of RAM needed
→ Fast CPU expected
→ Plugged into power

Not suitable for phones (2008):
→ Too slow
→ Too much memory
→ Battery drain
```

### Dalvik (Android 2.x — 4.x, now deprecated)

```
Android's custom VM:
→ Register-based (vs JVM's stack-based)
→ 30% faster for phones
→ .dex format (all classes in ONE file)
→ Used JIT compilation

JIT (Just In Time):
App launches → runs interpreted (slow)
→ Detects hot methods (run frequently)
→ Compiles those to machine code
→ Next run: machine code (fast)

Problem with JIT:
→ Compilation happens AT RUNTIME
→ Drains battery
→ Slow app startup (compiles fresh each launch)
→ Compiled code NOT saved to disk
→ Next launch = compile again
```

### ART (Android 5.0+, current)

```
ART = Android RunTime
Uses AOT (Ahead Of Time) compilation

Install time (happens ONCE):
.dex → dex2oat → .oat file (real machine code)
                     ↓
              Stored on disk permanently

Launch time:
.oat → run directly → NO translation → FAST
```

### Current Hybrid (Android 7+)

```
Best of both worlds:

First launch:
→ JIT runs the app
→ Profiles: "which methods run most?"

Background (charging/idle):
→ dex2oat compiles ONLY hot methods
→ Saves storage vs full AOT
→ Saves install time

Next launches:
→ Hot methods: machine code (fast)
→ Cold methods: JIT (rarely used, fine)
```

### File Locations

```
.apk file:           /data/app/com.example.app-1.apk
.dex inside APK:     classes.dex (compressed inside APK)
.oat compiled code:  /data/dalvik-cache/
                     data@app@com.example.app-1.apk@classes.dex
.vdex verified dex:  /data/dalvik-cache/ (ART optimization)
```

### VAPT Relevance

```
classes.dex = your app's entire code (decompilable)

# Extract and decompile:
apktool d target.apk           ← decompile to smali
jadx-gui target.apk            ← decompile to Java
dex2jar target.apk             ← convert dex to jar
jd-gui target-dex2jar.jar      ← view jar as Java

Dalvik-cache for analysis:
/data/dalvik-cache/ ← optimized files, can be used in forensics
```

---

## 10. Code Signing

### Why Sign Code?

```
Without signing:
Attacker downloads Gmail APK → injects malware → republishes
Users install fake Gmail → account stolen

With signing:
Attacker modifies APK → Google's signature BREAKS
Android detects tampering → REJECTED. Not installed.
```

**What signing does NOT solve:**
```
❌ Is the app SAFE?
❌ Is the developer TRUSTWORTHY?
✅ Was it tampered with?
✅ Did the same developer make this?
```

### APK File Structure

```
myapp.apk (ZIP file)
├── META-INF/
│   ├── MANIFEST.MF    ← fingerprints of ALL files
│   ├── CERT.SF        ← fingerprint of MANIFEST.MF
│   └── CERT.RSA       ← actual signature + certificate
├── classes.dex         ← compiled app code
├── AndroidManifest.xml
└── res/                ← images, layouts
```

### Three Security Files Explained

**MANIFEST.MF — The Inventory:**
```
Name: classes.dex
SHA1: abc123def456...

Name: res/drawable/icon.png
SHA1: K/0Rd/lt0qSlgDD/9DY7aCNlBvU=

Change even ONE byte → SHA1 hash changes completely
```

**CERT.SF — Fingerprint of fingerprints:**
```
SHA1-of-entire-MANIFEST.MF: zb0XjEhVBxE0z2ZC+B4OW25WBxo=

Also fingerprints each MANIFEST entry:
Name: classes.dex
SHA1-of-manifest-entry: abc789...
```

**CERT.RSA — The actual signature:**
```
Contains:
├── Digital signature (signed with developer's PRIVATE key)
└── Developer's certificate (who signed it)
```

### The Chain of Trust

```
Files → hashed → MANIFEST.MF
MANIFEST.MF → hashed → CERT.SF
CERT.SF → signed with private key → CERT.RSA

Verification (backwards):
CERT.RSA → verify signature → CERT.SF trusted?
CERT.SF  → verify hashes   → MANIFEST.MF trusted?
MANIFEST → verify hashes   → all files trusted?
ALL PASS → install ✅
ANY FAIL → reject ❌
```

### Android vs Traditional Signing

**Traditional (iOS, Windows):**
```
Certificate from trusted CA required
CA verifies identity
CA charges money
Certificate has chain of trust
```

**Android:**
```
Self-signed certificate = PERFECTLY FINE ✅
No CA needed
No identity verification
Expired certificate = Android still installs ✅
Subject name = can be "Batman" = fine ✅
```

**Android only cares about:**
```
"Is this update signed with the SAME key as before?"
YES = same developer = allow
NO  = different developer = REJECT
```

### Platform Keys (4 keys)

```
platform key  → core OS: Settings, SystemUI, Phone, Bluetooth
shared key    → Contacts, Search
media key     → Gallery, MediaProvider
testkey       → everything else (NEVER production)
               ⚠️ Public key in AOSP
               ⚠️ Anyone can sign malware with it
               ⚠️ Production builds with testkey = vulnerable
```

### Verification Process at Install

```
Step 1: Read CERT.RSA
        Extract certificate + signature

Step 2: Verify signature
        Decrypt with public key → compare with CERT.SF
        Match? → CERT.SF untouched ✅

Step 3: Verify CERT.SF
        Recalculate MANIFEST.MF hash
        Compare → MANIFEST.MF untouched ✅

Step 4: Verify MANIFEST.MF
        Recalculate hash of EVERY file
        All match → no file tampered ✅

Step 5: All pass → install
        Any fail → REJECTED
```

### OTA Update Signing

```
Problem: OTA package needs WHOLE FILE signed
         (updates modify system before Android runs)

Solution: Signature hidden in ZIP comment section
ZIP file: [actual content][signature block][6-byte offset record]
                                            ↑ "signature starts here"

Recovery reads END of file first:
→ Finds offset → reads signature → verifies entire file
→ THEN extracts and applies update

Trust chain:
OTA trusted certs: /system/etc/security/otacerts.zip
Android checks → reboot → Recovery checks AGAIN independently
Double verification
```

### Signing Tools

```bash
# Sign APK (standard Java tool)
jarsigner -keystore mykey.jks myapp.apk myalias

# Verify APK signature
jarsigner -verify -verbose -certs myapp.apk

# View signer info
keytool -list -printcert -jarfile myapp.apk

# Sign with Android-specific tool
java -jar signapk.jar cert.pem key.pk8 input.apk output.apk

# Extract signing certificate
unzip -q -c myapp.apk META-INF/CERT.RSA | openssl pkcs7 -inform DER -print_certs
```

### VAPT Relevance

```
Check signing:
apksigner verify --verbose target.apk
keytool -list -printcert -jarfile target.apk

Look for:
→ testkey used in production (serious issue)
→ Weak key size (< 2048 bits RSA)
→ Weak hash algorithm (MD5, SHA1)
→ Debug certificate in production
→ Certificate expiry (not a security issue in Android but check anyway)

Repackaging attack:
1. Decompile APK with apktool
2. Inject malicious code
3. Rebuild and re-sign with your own key
4. Install alongside original (different package name) or as update (same package name — will fail)
```

---

## 11. Package Management Internals

### The 6 Workers Team

```
APK arrives
    ↓
┌─────────────────────────────────────┐
│  PackageManagerService  ← THE BOSS  │
│  Installer class        ← Messenger │
│  installd daemon        ← File ops  │
│  MountService           ← Storage   │
│  vold daemon            ← Mounting  │
│  MediaContainerService  ← Copier    │
│  AppDirObserver         ← Watcher   │
└─────────────────────────────────────┘
```

### PackageManagerService (PMS)

The central brain:
```
Responsibilities:
→ Parse APK files
→ Verify signatures
→ Coordinate installation
→ Handle upgrades/uninstalls
→ Maintain packages.xml database
→ Manage permissions
→ Assign UIDs

Runs as:    system UID (1000)
Has root?   NO — delegates privileged ops to others
```

### Installer Class

```
PMS → needs file operations → delegates to:
Installer class → messenger to installd
→ Talks via /dev/socket/installd Unix socket
→ Converts Java calls into socket commands
```

### installd Daemon

```
The actual file system worker:
→ Creates app directories
→ Sets ownership
→ Runs dexopt/dex2oat

Special Linux capabilities:
CAP_DAC_OVERRIDE → bypass file permission checks
CAP_CHOWN        → change ownership of any file

Socket: /dev/socket/installd
Accessible: ONLY to system UID (1000)
Runs as: NOT root (old Android did, now uses capabilities only)
```

### MountService & vold

```
MountService (system UID):
→ API for SD cards, OBB files, encryption
→ Manages secure containers (ASEC)
→ Cannot actually mount (no privileges)
→ Delegates to vold

vold daemon (runs as ROOT):
→ Actually mounts/unmounts filesystems
→ Creates/formats filesystems
→ Manages encrypted containers
→ Socket: /dev/socket/vold
→ Accessible: only root + mount group (GID 1009)
→ system_server has GID 1009 → can reach vold
```

### MediaContainerService

```
The file copier:
→ Copies APK from download location to final destination
→ Handles decryption of encrypted APKs
→ Creates encrypted containers for forward-locked apps
→ Receives temporary URI permission to access downloaded APK
```

### AppDirObserver

```
Watches these directories for APK changes:
/system/framework/     ← framework-res.apk
/system/app/           ← system apps
/system/priv-app/      ← privileged system apps
/system/vendor/app/    ← vendor apps
/data/app/             ← user installed apps
/data/app-private/     ← old forward-locked APKs

APK ADDED → triggers package scan → install/update
APK REMOVED → triggers uninstall → removes files + database entry

Uses Linux inotify facility under the hood
One AppDirObserver instance per watched directory
```

### Security Through Least Privilege

```
Why this complex separation?

Each worker has MINIMUM power needed:
PMS            → system UID, no root — only manages logic
installd       → no root, just CAP_CHOWN + CAP_DAC_OVERRIDE
vold           → root, but only reachable by mount group
MediaContainer → temporary URI permissions only

If attacker exploits PMS:
→ Gets system UID (1000)
→ Cannot directly create files (needs installd)
→ Cannot mount volumes (needs vold)
→ Damage is LIMITED

Old design (everything as root):
→ One exploit → full device compromise
```

---

## 12. APK Install Process

### Complete 9-Step Flow

```
TAP INSTALL
    ↓
Step 1: TRUST CHECK
Step 2: PARSE & VERIFY APK
Step 3: SHOW PERMISSIONS DIALOG
Step 4: COPY APK TO /data/app/
Step 5: PACKAGE SCAN
Step 6: CREATE DATA DIRECTORIES
Step 7: GENERATE OPTIMIZED DEX
Step 8: WRITE TO packages.xml
Step 9: REGISTER COMPONENTS & BROADCAST
```

### Step 1 — Trust Check

```
PackageInstallerActivity checks:
"Where did this APK come from?"

Play Store? → TRUSTED ✅ proceed
Unknown source?
  → Check Settings.Global.INSTALL_NON_MARKET_APPS
  → TRUE (user enabled) → proceed with warning
  → FALSE (default) → BLOCKED
```

### Step 2 — Parse & Verify

```
Reads AndroidManifest.xml:
→ package name, version, permissions, components, certificate

Verifies EVERY file hash:
→ Recalculates SHA of each file
→ Compares with MANIFEST.MF
→ ALL match? → proceed ✅
→ ANY mismatch? → REJECTED ❌

System apps: only AndroidManifest.xml verified (implicitly trusted)
User apps:   EVERY single file verified

Anti-tamper trick (TOCTOU prevention):
→ AndroidManifest.xml hash calculated and stored
→ Later during copy: hash recalculated and compared
→ Ensures APK wasn't swapped between "user pressed OK" and actual copy
```

### Step 3 — Permissions Dialog

```
Shows user all requested permissions
User taps INSTALL
→ PackageInstallerActivity passes to InstallAppProgress:
   → APK file URI
   → manifest hash (anti-tamper)
   → referrer URL (where APK came from)
   → installer package name

InstallAppProgress calls:
PackageManagerService.installPackageWithVerificationAndEncryption()

PMS first checks:
"Does caller have INSTALL_PACKAGES permission?"
→ signature protection level
→ Only system apps can install
→ User apps CANNOT trigger installation directly
```

### Step 4 — Copy APK

```
PMS creates temp file: /data/app/vmdl[random].tmp
Delegates to MediaContainerService:
→ Copies APK into temp file
→ May decrypt if encrypted
→ May create encrypted container if forward-locked

After copy:
Extract native .so files → /data/app-lib/com.example.app-1/

Rename temp to final:
/data/app/vmdl12345.tmp → /data/app/com.example.app-1.apk
/data/app-lib/tmp/       → /data/app-lib/com.example.app-1/

Set permissions:
APK → 0644 (world readable — needed for launchers/tools)
SELinux context set on APK file
```

### Step 5 — Package Scan

```
PMS calls scanPackageLI()

Creates PackageSettings:
├── package name: com.example.app
├── code path: /data/app/com.example.app-1.apk
├── native lib path: /data/app-lib/com.example.app-1/
└── UID: 10215 (newly assigned, starts from 10000)

New install: assign next available UID
Update: keep SAME UID as before (data stays accessible)
```

### Step 6 — Create Data Directories

```
PMS → Installer class → installd daemon
installd receives: install(com.example.app, uid=10215, gid=10215)

Creates:
/data/data/com.example.app/           → 0751 u0_a215:u0_a215
/data/data/com.example.app/cache/     → 0771 u0_a215:u0_a215
/data/data/com.example.app/databases/ → 0771 u0_a215:u0_a215
/data/data/com.example.app/files/     → 0771 u0_a215:u0_a215
/data/data/com.example.app/lib/       → symlink → /data/app-lib/...

Multi-user: mkuserdata command creates per-user directories
```

### Step 7 — Generate Optimized DEX

```
installd receives: dexopt (or dex2oat for ART)

.dex → dexopt → /data/dalvik-cache/data@app@com.example.app-1.apk@classes.dex

Ownership trick for multi-user:
owner: system
group: all_a215  ← special group = ALL users who installed this app
→ Multiple users share ONE compiled DEX file
→ No need to recompile for each user
→ Saves massive disk space
```

### Step 8 — Write to packages.xml

```xml
<package
    name="com.example.app"
    codePath="/data/app/com.example.app-1.apk"
    nativeLibraryPath="/data/app-lib/com.example.app-1"
    flags="572996"
    ft="142dfa0e588"      ← APK file timestamp
    it="142cbeac305"      ← first install time
    ut="142dfa0e8d7"      ← last update time
    version="1"
    userId="10215"
    installer="com.android.vending">  ← who installed it
    <sigs count="1">
        <cert index="7" key="30820252..."/>  ← signing certificate (hex)
    </sigs>
    <perms>
        <item name="android.permission.INTERNET"/>
        <item name="android.permission.CAMERA"/>
    </perms>
</package>
```

### Step 9 — Register & Broadcast

```
PMS scans manifest again:
→ Registers Activities, Services, Receivers, Providers in memory
→ Other apps can now find and communicate with them

Sends broadcast: ACTION_PACKAGE_ADDED
→ Launchers add new app icon
→ App stores update installed list
→ System updates app drawer
```

### "First One Wins" Custom Permission Vulnerability

```
App A defines: com.example.MY_PERM (signature level) → installs first ✅
App B defines: com.example.MY_PERM (normal level)    → installs second
Result: MY_PERM = signature level (App A wins, B's definition ignored)

DANGEROUS SCENARIO:
App B installs FIRST (normal level registered)
App A installs second → signature level IGNORED
MY_PERM stays normal level → ANY app can get it!

VAPT CHECK: Verify custom permission protection levels match expected
```

---

## 13. Package Updates

### Same Origin Policy (TOFU — Trust On First Use)

```
First install: key fingerprint stored
Every update:  MUST use same key fingerprint

Android compares certificates byte-by-byte:
current_cert_bytes == update_cert_bytes?
YES → allow update
NO  → INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES
```

**What Android does NOT check:**
```
❌ Certificate expired?
❌ Trusted CA?
❌ Certificate chain valid?
✅ ONLY: raw bytes identical?
```

### Updating Non-System Apps

```
v2 update arrives, signature matches ✅

1. Kill existing process
2. Remove from memory registry and packages.xml
3. Keep /data/data/com.example.app/ INTACT (data preserved)
4. scanPackageLI() — update code path, version, timestamp
5. Keep SAME UID (data stays accessible)
6. Re-grant all permissions (match new manifest)
7. Write updated packages.xml
8. Broadcast PACKAGE_REPLACED
```

### Updating System Apps

```
System apps in /system/app/ (READ ONLY partition)
Cannot write to /system/app/
→ Install update to /data/app/ instead
→ Keep original in /system/app/ untouched

Two entries in packages.xml:
<package codePath="/data/app/keep-1.apk" version="2101" userId="10053">
    → newer version, used at runtime
<updated-package codePath="/system/app/Keep.apk" version="2051" userId="10053">
    → original, kept as fallback

If user uninstalls update:
→ /data/app/ version deleted
→ Falls back to /system/app/ original automatically
```

### System App Signature Rules

```
Normal app update: MUST use same key (no exceptions)

System app OTA (writing directly to /system):
→ CAN use different signing key
→ Logic: "If you can write to /system, we trust you"

Exception: if app uses sharedUserId
→ CANNOT change certificate even via OTA
→ Would break trust for ALL apps sharing that UID
```

### Key Loss = App Death

```
Lost your keystore?
→ Cannot sign v2 with same key
→ Cannot update existing users' app
→ Must publish as completely NEW app
→ All users must uninstall + reinstall
→ All reviews/ratings LOST
→ All install count LOST

Recommendations:
→ Backup keystore FOREVER
→ Certificate validity: minimum 25 years
→ Google Play requires valid until at least October 2033
→ Use Play App Signing (Google stores key safely)
```

---

## 14. Encrypted APKs & Forward Locking

### Why This Exists

```
Normal APK in /data/app/:
Permissions: 0644 = WORLD READABLE

adb pull /data/app/com.example.app.apk
→ Got paid app for FREE
→ Share with millions
→ Developer loses money

Two protection mechanisms:
Encrypted APK     → protects during TRANSFER
Forward Locking   → protects ON DEVICE storage
```

### Encrypted APK Installation

```bash
# Encrypt APK with AES-128-CBC
openssl enc -aes-128-cbc \
    -K  000102030405060708090A0B0C0D0E0F \
    -iv 000102030405060708090A0B0C0D0E0F \
    -in myapp.apk -out myapp-encrypted.apk

# Install encrypted APK
adb install \
    --algo 'AES/CBC/PKCS5Padding' \
    --key  000102030405060708090A0B0C0D0E0F \
    --iv   000102030405060708090A0B0C0D0E0F \
    myapp-encrypted.apk
```

**What happens:**
```
MediaContainerService.copyResource() receives ContainerEncryptionParams:
→ Creates Cipher (decryption engine) with provided params
→ Decrypts APK on-the-fly while copying
→ Decrypted APK lands in /data/app/ (plain)
→ Normal install continues

Key insight: Encrypted during TRANSFER, decrypted at INSTALL
Final APK on device = UNENCRYPTED
```

### MAC — Integrity Check

```bash
# Calculate HMAC of encrypted APK
openssl dgst -hmac 'hmac_key_1' -sha1 -hex myapp-encrypted.apk
# → 962ecdb4e99551f6c2cf72f641362d657164f55a

# Install with integrity verification
pm install \
    --algo 'AES/CBC/PKCS5Padding' \
    --key  000102030405060708090A0B0C0D0E0F \
    --iv   000102030405060708090A0B0C0D0E0F \
    --macalgo HmacSHA1 \
    --mackey  686d61635f6b65795f31 \
    --tag     962ecdb4e99551f6c2cf72f641362d657164f55a \
    myapp-encrypted.apk
```

**Process:**
```
1. Calculate MAC of received file
   Compare with --tag value
   Match? ✅ proceed / No match? ❌ INSTALL_FAILED_INVALID_APK

2. Decrypt using key+iv+algo

3. Copy decrypted APK to /data/app/
```

### Forward Locking (ASEC Containers)

**The concept — split the APK:**
```
Normal APK = one file with everything

Forward Locked APK = SPLIT:

Part 1: Public (world readable)
→ res.zip: images, layouts, manifest
→ Launchers need this for icons
→ /mnt/asec/com.example.app-1/res.zip (rw-r--r--)

Part 2: Private (encrypted, restricted)
→ pkg.apk: actual code (classes.dex)
→ Only system + app's UID can read
→ /mnt/asec/com.example.app-1/pkg.apk (rw-r-----)
```

**ASEC = Android Secure External Cache:**
```
Encrypted vault on device:
Container file:  /data/app-asec/com.example.app-1.asec
Mount point:     /mnt/asec/com.example.app-1/

Encryption:      Twofish 128-bit (NOT AES)
Key stored:      /data/misc/systemkeys/AppsOnSD.sks
                 16 bytes, owned by system only (rw-------)
                 DEVICE SPECIFIC key
                 → Steal .asec file → useless on other device
```

**ASEC Management:**
```bash
vdc asec list                          # list mounted containers
vdc asec path com.example.app-1        # find mount point
vdc asec unmount com.example.app-1     # unmount
vdc asec mount com.example.app-1 [key] 1000  # mount
```

**Install flow for forward-locked:**
```
pm install -l myapp.apk   ← -l flag = forward lock
    ↓
PackageManagerService → sets INSTALL_FORWARD_LOCK flag
    ↓
MediaContainerService → calls MountService.createSecureContainer()
    ↓
MountService → vold daemon
→ vold creates .asec file in /data/app-asec/
→ Formats with ext4 inside container
→ Mounts at /mnt/asec/com.example.app-1/
    ↓
MediaContainerService:
→ Full APK → /mnt/asec/.../pkg.apk (rw-r-----)
→ Resources → /mnt/asec/.../res.zip (rw-r--r--)
    ↓
Normal install continues
```

### Google Play Integration

```
Free app:
→ Downloaded plain or encrypted
→ Decrypted at install
→ Lands in /data/app/ (plain)

Paid app:
→ Downloaded encrypted (AES/CBC/PKCS5Padding + HMACSHA1)
→ INSTALL_FORWARD_LOCK flag set
→ Decrypted then stored in /data/app-asec/
→ Mounted at /mnt/asec/
```

### Security Reality

```
Against normal users:     ✅ Effective
Against ADB extraction:   ✅ Effective (file permissions block it)
Against rooted devices:   ❌ NOT effective

Root access:
→ Read /data/misc/systemkeys/AppsOnSD.sks → get encryption key
→ Mount container manually → extract pkg.apk

OR:
→ Dump process memory while app running → get decrypted code

This is why Google moved to:
→ Play Integrity API (server-side attestation)
→ SafetyNet
→ Forward locking = extra barrier, not perfect
```

---

## 15. Package Verification

### What is Package Verification?

```
Before installing any APK → send it to a verifier
Verifier analyzes → potentially harmful? → block or warn

Introduced: Android 4.2 (backported to 2.3+)
Built into OS but: Android ships with NO default verifiers
Most used verifier: Google Play Store client
```

### Verification Architecture

```
Required verifier:
→ ONE required verifier must approve
→ Must have PACKAGE_VERIFICATION_AGENT permission (signature|system)
→ Only system apps can be required verifiers

Sufficient verifiers:
→ Zero or more additional verifiers
→ At least ONE sufficient verifier must also approve
→ Declared via <package-verifier> tag in manifest

Verification complete when:
Required verifier approved AND at least one sufficient verifier approved
```

**Register as required verifier:**
```xml
<receiver android:name=".MyVerificationReceiver"
    android:permission="android.permission.BIND_PACKAGE_VERIFIER">
    <intent-filter>
        <action android:name="android.intent.action.PACKAGE_NEEDS_VERIFICATION"/>
        <action android:name="android.intent.action.PACKAGE_VERIFIED"/>
        <data android:mimeType="application/vnd.android.package-archive"/>
    </intent-filter>
</receiver>
```

### Verification Flow

```
Install requested
    ↓
PMS: is required verifier installed AND PACKAGE_VERIFIER_ENABLE=true?
    ↓
YES: Add to pending installs queue
     Send ACTION_PACKAGE_NEEDS_VERIFICATION broadcast
     (contains: unique verification ID, package metadata)
    ↓
Verifier receives broadcast
Analyzes APK
Calls: verifyPendingInstall(verificationId, status)
    ↓
PMS checks: sufficient verification received?
    YES → remove from queue → send PACKAGE_VERIFIED → install
    NO/timeout → INSTALL_FAILED_VERIFICATION_FAILURE
```

### Google Play's Implementation

```
Play Store registers as required verifier
If "Verify Apps" is ON:
→ Every APK install triggers verification broadcast
→ Even adb install, PackageInstaller — ALL installs verified

What Google receives:
→ APK SHA-256 hash
→ File size
→ Package name
→ Resource names + SHA-256 hashes
→ Manifest + classes SHA-256 hashes
→ Version code
→ Signing certificates
→ Installer app metadata
→ Referrer URLs
→ Device ID, OS version, IP address

Google's algorithms determine:
→ Potentially harmful? → block/warn
→ Safe? → proceed
```

---

```


### OWASP Mobile Top 10 — Android Mapping

| OWASP | Android Internals Connection |
|-------|---------------------------|
| M1 — Improper Credential Usage | Hardcoded keys/passwords in classes.dex |
| M2 — Inadequate Supply Chain Security | testkey signing, unverified APKs |
| M3 — Insecure Authentication | Broken permission checks in Binder services |
| M4 — Insufficient Input/Output Validation | Content Provider SQL injection |
| M5 — Insecure Communication | cleartext traffic, no SSL pinning |
| M6 — Inadequate Privacy Controls | SharedPrefs/SQLite sensitive data |
| M7 — Insufficient Binary Protections | Debuggable=true, no code obfuscation |
| M8 — Security Misconfiguration | Exported components without permissions |
| M9 — Insecure Data Storage | World-readable files, external storage |
| M10 — Insufficient Cryptography | Weak algorithms, hardcoded keys, ECB mode |

### Key Architecture 

```
Binder:
→ All cross-process calls go through /dev/binder
→ PID/UID stamped by kernel — unfakeable
→ But: if service doesn't check UID → anyone can call it

Sandbox:
→ Each app = unique UID
→ Files owned by that UID
→ Breaking sandbox = major vulnerability

Permissions:
→ Dangerous permissions require user approval
→ But: permissions granted at install, never revoked
→ Permission downgrade via "first one wins" custom perms

Intents:
→ Explicit = specific target (safe)
→ Implicit = anyone can handle (risky)
→ Exported components + no permission = attack surface

Content Providers:
→ readPermission / writePermission separate
→ Per-URI permissions can override global
→ SQL injection via content URI parameters
→ Path traversal in file providers

Pending Intents:
→ Carry creator's identity + permissions
→ Vague base intent → hijackable by malicious app

Forward Locking:
→ ASEC container = encrypted vault
→ Root access bypasses it
→ Key at /data/misc/systemkeys/AppsOnSD.sks
```

---

## Resources for Deep Dive

### Books
| Book | Why Read |
|------|---------|
| Android Security Internals (Elenkov) | These notes are based on it |
| Mobile Application Hacker's Handbook | Attack techniques |
| Hacking APIs (Corey Ball) | Most apps = API clients |

### Free Resources
| Resource | URL |
|----------|-----|
| HackTricks Android | book.hacktricks.xyz/mobile-pentesting/android-app-pentesting |
| OWASP MSTG | mas.owasp.org |
| Frida Docs | frida.re/docs |


*Notes by: toklas495*

