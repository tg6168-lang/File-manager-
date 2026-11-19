package com.example.filemanager.extensions

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import com.example.R
import com.google.android.gms.tasks.Task
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.Companion.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
import com.google.firebase.Firebase
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
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
 * Optional Google Sign-In Portal powered by Firebase Authentication + Jetpack Credential Manager.
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
            _authState.value = GoogleAuthUiState.Error(
                message = "Thiếu cấu hình default_web_client_id trong google-services.json.",
                previousProfile = auth.currentUser?.toProfile()
            )
            return
        }

        val previousProfile = auth.currentUser?.toProfile()
        _authState.value = GoogleAuthUiState.Loading("Đang mở chọn tài khoản Google...")

        managerScope.launch {
            try {
                val credentialManager = CredentialManager.create(activity)
                val signInOption = GetSignInWithGoogleOption.Builder(serverClientId = serverClientId).build()
                val request = GetCredentialRequest.Builder()
                    .addCredentialOption(signInOption)
                    .build()

                val response = credentialManager.getCredential(activity, request)
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
                    _authState.value = GoogleAuthUiState.Error(
                        message = "Loại thông tin xác thực không hợp lệ.",
                        previousProfile = previousProfile
                    )
                }
            } catch (e: GetCredentialCancellationException) {
                Log.w(TAG, "Google Sign-In flow cancelled or dismissed: ${e.message}", e)
                _authState.value = previousProfile?.let { GoogleAuthUiState.SignedIn(it) }
                    ?: GoogleAuthUiState.SignedOut
            } catch (e: NoCredentialException) {
                Log.w(TAG, "No Google credential available on device: ${e.message}", e)
                _authState.value = GoogleAuthUiState.Error(
                    message = "Thiết bị chưa có tài khoản Google hoặc dịch vụ Google Play chưa sẵn sàng.",
                    previousProfile = previousProfile
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "Google Sign-In notice: ${e.message}")
                _authState.value = GoogleAuthUiState.Error(
                    message = "Đăng nhập Google chưa thành công: ${e.localizedMessage ?: "Vui lòng thử lại."}",
                    previousProfile = previousProfile
                )
            }
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
