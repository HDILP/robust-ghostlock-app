package com.ghostlock.app.domain.model

/**
 * Classifies a completed run's log and exit code into a user-facing verdict.
 *
 * Shared across `data` (so the DirtyFrag pipeline does not run after a
 * `KernelSU already has root` early stop) and `ui` (so the sheet status,
 * log summary, and notification agree on one source of truth).
 */
object RunVerdict {
    enum class Outcome(val isRooted: Boolean) {
        ROOTED_GHOSTLOCK(true),
        ROOTED_DIRTYFRAG(true),
        ALREADY_ROOTED(true),
        FAILED(false),
    }

    fun isAlreadyRootedSkip(log: String): Boolean =
        log.contains("KernelSU already has root")

    fun classify(log: String, exitCode: Int): Outcome = when {
        exitCode != 0 -> Outcome.FAILED
        log.contains("RESULT=OK") -> Outcome.ROOTED_DIRTYFRAG
        log.contains("KernelSU ready") -> Outcome.ROOTED_GHOSTLOCK
        isAlreadyRootedSkip(log) -> Outcome.ALREADY_ROOTED
        else -> Outcome.FAILED
    }
}
