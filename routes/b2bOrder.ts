/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function isMalicious (input: string): boolean {
  // Normalize Unicode normalization form KC (Compatibility Decomposition)
  let normalized = input.normalize('NFKC')

  // Normalize hex escapes (\xHH) and unicode escapes (\uHHHH or \u{HHHH})
  normalized = normalized.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  normalized = normalized.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  normalized = normalized.replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  // Normalize octal escapes (e.g., \143)
  normalized = normalized.replace(/\\([0-7]{1,3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)))

  // Create a clean version of the normalized string with common obfuscation characters removed
  const clean = normalized.toLowerCase().replace(/['"`\s\+\[\]\.\$\{\}\(\),:\\\-]/g, '')

  const blacklisted = [
    'constructor',
    'prototype',
    '__proto__',
    'process',
    'require',
    'child_process',
    'exec',
    'spawn',
    'global',
    'function',
    'eval',
    'import',
    'fs',
    'mainmodule',
    'atob',
    'btoa',
    'fromcharcode',
    'fromcodepoint',
    'charcodeat',
    'codepointat',
    'concat',
    'slice',
    'substr',
    'substring',
    'replace',
    'join',
    'reverse',
    'split',
    'reduce',
    'map',
    'this',
    'window',
    'document',
    'self',
    'top',
    'parent',
    'frames',
    'reflect',
    'proxy',
    'object',
    'array',
    'string',
    'number',
    'boolean',
    'regexp',
    'error',
    'arguments',
    'callee',
    'caller',
    'promise',
    'symbol',
    'set'
  ]

  for (const term of blacklisted) {
    if (clean.includes(term)) {
      return true
    }
  }

  const lowerNormalized = normalized.toLowerCase()
  for (const term of blacklisted) {
    if (lowerNormalized.includes(term)) {
      return true
    }
  }

  return false
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      let orderLinesData = body.orderLinesData || ''
      if (typeof orderLinesData !== 'string') {
        orderLinesData = JSON.stringify(orderLinesData)
      }

      if (isMalicious(orderLinesData)) {
        res.status(400)
        return next(new Error('Invalid order lines data'))
      }

      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
