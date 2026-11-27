package com.ghostlock.app.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RunVerdictTest {
    @Test
    fun `ghostlock marker with zero exit classifies as rooted ghostlock`() {
        val outcome = RunVerdict.classify(
            "[*] page_free=1\n[+] KernelSU ready\n",
            0,
        )
        assertEquals(RunVerdict.Outcome.ROOTED_GHOSTLOCK, outcome)
        assertTrue(outcome.isRooted)
    }

    @Test
    fun `dirtyfrag result ok with zero exit classifies as rooted dirtyfrag`() {
        val outcome = RunVerdict.classify(
            "<b> pipeline=dirtyfrag\ndirtyfrag: T+1200ms RESULT=OK script=0 enforce=1\n",
            0,
        )
        assertEquals(RunVerdict.Outcome.ROOTED_DIRTYFRAG, outcome)
        assertTrue(outcome.isRooted)
    }

    @Test
    fun `already rooted skip with zero exit classifies as already rooted`() {
        val log = "[-] KernelSU already has root; skipping exploit " +
            "(cold boot for a clean run, or enable the forced test)\n"
        assertTrue(RunVerdict.isAlreadyRootedSkip(log))
        val outcome = RunVerdict.classify(log, 0)
        assertEquals(RunVerdict.Outcome.ALREADY_ROOTED, outcome)
        assertTrue(outcome.isRooted)
    }

    @Test
    fun `bare exit zero without positive evidence classifies as failed`() {
        assertFalse(RunVerdict.isAlreadyRootedSkip("nothing happened\n"))
        val outcome = RunVerdict.classify("<b> native exited code=0\n", 0)
        assertEquals(RunVerdict.Outcome.FAILED, outcome)
        assertFalse(outcome.isRooted)
    }

    @Test
    fun `non-zero exit always classifies as failed even with markers`() {
        val markers = listOf(
            "[+] KernelSU ready\n",
            "dirtyfrag: T+1200ms RESULT=OK script=0 enforce=1\n",
            "[-] KernelSU already has root; skipping exploit\n",
        )
        for (log in markers) {
            assertEquals(RunVerdict.Outcome.FAILED, RunVerdict.classify(log, 1))
            assertEquals(RunVerdict.Outcome.FAILED, RunVerdict.classify(log, -1))
            assertFalse(RunVerdict.classify(log, 1).isRooted)
        }
    }
}
