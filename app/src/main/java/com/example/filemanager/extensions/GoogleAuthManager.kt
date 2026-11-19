package com.example.filemanager.extensions

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.MutableContextWrapper
import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import com.example.R
import com.google.android.gms.tasks.Task
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.Companion.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
import com.google.firebase.Firebase
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.OAuthProvider
import com.google.firebase.auth.auth
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class GoogleAccountProfile(
    val uid: String,
    val displayName: String,
    val email: String,
    val photoUrl: String? = null
)

sealed interface GoogleAuthUiState {
    data object SignedOut : GoogleAuthUiState
    data class Loading(val message: String = "Đang xử lý...") : GoogleAuthUiState
    data class SignedIn(val profile: GoogleAccountProfile) : GoogleAuthUiState
    data class Error(val message: String, val previousProfile: GoogleAccountProfile? = null) : GoogleAuthUiState
}

/**
 * Optional Google Sign-In Portal powered by Firebase Authentication + Jetpack Credential Manager,
 * with automatic fallback to GetGoogleIdOption and Firebase Browser OAuth (OAuthProvider) so sign-in
 * works reliably across real devices, custom ROMs, and emulators.
 * Offline File Manager functionality remains 100% available whether signed in or signed out.
 */
object GoogleAuthManager {
    private const val TAG = "GoogleAuthPortal"

    private val managerScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val auth: FirebaseAuth by lazy { Firebase.auth }

    private val _authState = MutableStateFlow<GoogleAuthUiState>(
        auth.currentUser?.toProfile()?.let { GoogleAuthUiState.SignedIn(it) } ?: GoogleAuthUiState.SignedOut
    )
    val authState: StateFlow<GoogleAuthUiState> = _authState.asStateFlow()

    private val authListener = FirebaseAuth.AuthStateListener { firebaseAuth ->
        val current = firebaseAuth.currentUser?.toProfile()
        val existingState = _authState.value
        if (existingState !is GoogleAuthUiState.Loading) {
            _authState.value = if (current != null) {
                GoogleAuthUiState.SignedIn(current)
            } else {
                GoogleAuthUiState.SignedOut
            }
        }
    }

    init {
        try {
            auth.addAuthStateListener(authListener)
            // Recover any pending browser OAuth sign-in result if Activity was recreated
            auth.pendingAuthResult?.addOnSuccessListener { res ->
                val profile = (res.user ?: auth.currentUser)?.toProfile()
                if (profile != null) {
                    _authState.value = GoogleAuthUiState.SignedIn(profile)
                }
            }?.addOnFailureListener { exc ->
                Log.w(TAG, "Pending OAuth result failed: ${exc.message}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "FirebaseAuth listener init notice: ${e.message}")
        }
    }

    fun signInWithGoogle(context: Context) {
        val activity = context.findActivity()
        if (activity == null) {
            _authState.value = GoogleAuthUiState.Error(
                message = "Không thể mở hộp thoại đăng nhập từ ngữ cảnh hiện tại.",
                previousProfile = auth.currentUser?.toProfile()
            )
            return
        }

        val serverClientId = try {
            context.getString(R.string.default_web_client_id)
        } catch (_: Exception) {
            ""
        }
        if (serverClientId.isBlank() || serverClientId.contains("dummy", ignoreCase = true)) {
            signInWithGoogleWebOAuth(activity)
            return
        }

        val previousProfile = auth.currentUser?.toProfile()
        _authState.value = GoogleAuthUiState.Loading("Đang mở chọn tài khoản Google...")

        managerScope.launch {
            try {
                val credentialManager = CredentialManager.create(activity)
                val activityWrapper = MutableContextWrapper(activity)

                // Step 1: Official interactive GetSignInWithGoogleOption (1 option per request)
                val signInOption = GetSignInWithGoogleOption.Builder(serverClientId = serverClientId).build()
                val primaryRequest = GetCredentialRequest.Builder()
                    .addCredentialOption(signInOption)
                    .build()

                val response = try {
                    credentialManager.getCredential(activityWrapper, primaryRequest)
                } catch (e: GetCredentialCancellationException) {
                    Log.w(TAG, "Google Sign-In flow cancelled or dismissed: ${e.message}", e)
                    val rawMsg = e.message.orEmpty()
                    // If Play Services returned a developer/config/GMS internal error wrapped in cancellation,
                    // fall back seamlessly to Firebase Web OAuth; otherwise surface clear helper message.
                    val looksLikeConfigError = rawMsg.contains("28444") ||
                        rawMsg.contains("16:") ||
                        rawMsg.contains("developer console", ignoreCase = true) ||
                        rawMsg.contains("caller", ignoreCase = true)
                    if (looksLikeConfigError) {
                        launchFirebaseGoogleWebOAuth(activity, previousProfile)
                    } else {
                        _authState.value = GoogleAuthUiState.Error(
                            message = "Đã đóng hộp thoại Google One-Tap. Nếu cửa sổ không hiển thị, hãy bấm \"Đăng nhập qua trình duyệt\".",
                            previousProfile = previousProfile
                        )
                    }
                    return@launch
                } catch (primaryErr: GetCredentialException) {
                    Log.w(TAG, "Primary GetSignInWithGoogleOption failed (${primaryErr::class.simpleName}): ${primaryErr.message}")
                    // Step 2: Try GetGoogleIdOption(filterByAuthorizedAccounts = false) before Web OAuth
                    try {
                        val fallbackOption = GetGoogleIdOption.Builder()
                            .setFilterByAuthorizedAccounts(false)
                            .setServerClientId(serverClientId)
                            .setAutoSelectEnabled(false)
                            .build()
                        val fallbackRequest = GetCredentialRequest.Builder()
                            .addCredentialOption(fallbackOption)
                            .build()
                        credentialManager.getCredential(activityWrapper, fallbackRequest)
                    } catch (cancelErr: GetCredentialCancellationException) {
                        Log.w(TAG, "Fallback GetGoogleIdOption cancelled: ${cancelErr.message}")
                        _authState.value = GoogleAuthUiState.Error(
                            message = "Đã đóng hộp thoại Google. Bạn có thể thử lại hoặc dùng \"Đăng nhập qua trình duyệt\".",
                            previousProfile = previousProfile
                        )
                        return@launch
                    } catch (fallbackErr: Exception) {
                        Log.w(TAG, "Credential Manager fallback failed (${fallbackErr::class.simpleName}): ${fallbackErr.message}; launching Web OAuth")
                        // Step 3: Universal Firebase OAuth via Browser / Custom Tab
                        launchFirebaseGoogleWebOAuth(activity, previousProfile)
                        return@launch
                    }
                }

                val cred = response.credential
                if (cred is CustomCredential && cred.type == TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                    val googleToken = GoogleIdTokenCredential.createFrom(cred.data).idToken
                    val firebaseCred = GoogleAuthProvider.getCredential(googleToken, null)
                    val authResult = auth.signInWithCredential(firebaseCred).awaitTask()
                    val profile = (authResult.user ?: auth.currentUser)?.toProfile()
                    _authState.value = if (profile != null) {
                        GoogleAuthUiState.SignedIn(profile)
                    } else {
                        GoogleAuthUiState.SignedOut
                    }
                } else {
                    Log.w(TAG, "Unexpected credential type: ${cred::class.java.name}")
                    launchFirebaseGoogleWebOAuth(activity, previousProfile)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: NoCredentialException) {
                Log.w(TAG, "No Google credential on device: ${e.message}", e)
                launchFirebaseGoogleWebOAuth(activity, previousProfile)
            } catch (e: GetCredentialUnsupportedException) {
                Log.w(TAG, "Credential Manager unsupported: ${e.message}", e)
                launchFirebaseGoogleWebOAuth(activity, previousProfile)
            } catch (e: GetCredentialProviderConfigurationException) {
                Log.w(TAG, "Credential Provider configuration notice: ${e.message}", e)
                launchFirebaseGoogleWebOAuth(activity, previousProfile)
            } catch (e: Exception) {
                Log.w(TAG, "Google Sign-In failed: ${e.message}", e)
                _authState.value = GoogleAuthUiState.Error(
                    message = "Đăng nhập Google chưa thành công: ${e.localizedMessage ?: "Vui lòng thử 'Đăng nhập qua trình duyệt'."}",
                    previousProfile = previousProfile
                )
            }
        }
    }

    /**
     * Opens Google OAuth login directly via Chrome Custom Tab / system browser through Firebase Auth.
     * Works on all Android devices and emulators regardless of Google Play Services Credential Manager state.
     */
    fun signInWithGoogleWebOAuth(context: Context) {
        val activity = context.findActivity()
        if (activity == null) {
            _authState.value = GoogleAuthUiState.Error(
                message = "Không thể mở trình duyệt đăng nhập từ ngữ cảnh hiện tại.",
                previousProfile = auth.currentUser?.toProfile()
            )
            return
        }
        val previousProfile = auth.currentUser?.toProfile()
        _authState.value = GoogleAuthUiState.Loading("Đang mở trang đăng nhập Google an toàn...")
        managerScope.launch {
            launchFirebaseGoogleWebOAuth(activity, previousProfile)
        }
    }

    private suspend fun launchFirebaseGoogleWebOAuth(
        activity: Activity,
        previousProfile: GoogleAccountProfile?
    ) {
        try {
            _authState.value = GoogleAuthUiState.Loading("Đang kết nối cổng đăng nhập Google...")
            val provider = OAuthProvider.newBuilder("google.com")
                .setScopes(listOf("email", "profile"))
                .addCustomParameter("prompt", "select_account")
                .build()

            val pending = auth.pendingAuthResult
            val result = if (pending != null) {
                pending.awaitTask()
            } else {
                auth.startActivityForSignInWithProvider(activity, provider).awaitTask()
            }

            val profile = (result.user ?: auth.currentUser)?.toProfile()
            _authState.value = if (profile != null) {
                GoogleAuthUiState.SignedIn(profile)
            } else {
                GoogleAuthUiState.SignedOut
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "Web OAuth sign-in notice: ${e.message}", e)
            val msg = e.localizedMessage.orEmpty()
            val friendly = when {
                msg.contains("canceled", ignoreCase = true) || msg.contains("cancelled", ignoreCase = true) ->
                    "Bạn đã hủy đăng nhập Google."
                msg.contains("network", ignoreCase = true) ->
                    "Không có kết nối Internet để đăng nhập Google."
                else ->
                    "Không thể hoàn tất đăng nhập Google: ${msg.ifBlank { "Vui lòng kiểm tra kết nối mạng và thử lại." }}"
            }
            _authState.value = GoogleAuthUiState.Error(
                message = friendly,
                previousProfile = previousProfile
            )
        }
    }

    fun signOut(context: Context, onComplete: (() -> Unit)? = null) {
        _authState.value = GoogleAuthUiState.Loading("Đang đăng xuất tài khoản...")
        managerScope.launch {
            withContext(NonCancellable) {
                try {
                    val credentialManager = CredentialManager.create(context.applicationContext)
                    credentialManager.clearCredentialState(ClearCredentialStateRequest())
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to clear credential state: ${e.message}")
                } finally {
                    try {
                        auth.signOut()
                    } catch (e: Exception) {
                        Log.w(TAG, "Firebase signOut notice: ${e.message}")
                    }
                    _authState.value = GoogleAuthUiState.SignedOut
                    onComplete?.invoke()
                }
            }
        }
    }

    fun switchAccount(context: Context) {
        signOut(context) {
            managerScope.launch {
                signInWithGoogle(context)
            }
        }
    }

    fun dismissError() {
        val current = auth.currentUser?.toProfile()
        _authState.value = if (current != null) {
            GoogleAuthUiState.SignedIn(current)
        } else {
            GoogleAuthUiState.SignedOut
        }
    }

    private fun FirebaseUser.toProfile(): GoogleAccountProfile {
        val fallbackName = email?.substringBefore("@")?.takeIf { it.isNotBlank() } ?: "Người dùng Google"
        return GoogleAccountProfile(
            uid = uid,
            displayName = displayName?.takeIf { it.isNotBlank() } ?: fallbackName,
            email = email.orEmpty(),
            photoUrl = photoUrl?.toString()
        )
    }

    private tailrec fun Context.findActivity(): Activity? = when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext.findActivity()
        else -> null
    }

    private suspend fun <T> Task<T>.awaitTask(): T = suspendCancellableCoroutine { cont ->
        addOnSuccessListener { result ->
            if (cont.isActive) cont.resume(result)
        }
        addOnFailureListener { exc ->
            if (cont.isActive) cont.resumeWithException(exc)
        }
        addOnCanceledListener {
            cont.cancel()
        }
    }
}
