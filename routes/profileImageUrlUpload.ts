/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import { promisify } from 'node:util'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const lookupPromise = promisify(dns.lookup)

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) return false

  const [o1, o2, o3, o4] = parts

  // 127.0.0.0/8 (Loopback)
  if (o1 === 127) return true

  // 10.0.0.0/8 (Private)
  if (o1 === 10) return true

  // 172.16.0.0/12 (Private)
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true

  // 192.168.0.0/16 (Private)
  if (o1 === 192 && o2 === 168) return true

  // 169.254.0.0/16 (Link-local)
  if (o1 === 169 && o2 === 254) return true

  // 0.0.0.0/8 (Current network / local)
  if (o1 === 0) return true

  // 100.64.0.0/10 (Carrier-grade NAT)
  if (o1 === 100 && o2 >= 64 && o2 <= 127) return true

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (o1 === 192 && o2 === 0 && o3 === 0) return true

  // 192.0.2.0/24 (Documentation / Test-Net-1)
  if (o1 === 192 && o2 === 0 && o3 === 2) return true

  // 198.18.0.0/15 (Network interconnect device benchmark testing)
  if (o1 === 198 && o2 >= 18 && o2 <= 19) return true

  // 198.51.100.0/22 (Documentation / Test-Net-2)
  if (o1 === 198 && o2 === 51 && o3 === 100) return true

  // 203.0.113.0/24 (Documentation / Test-Net-3)
  if (o1 === 203 && o2 === 0 && o3 === 113) return true

  // 224.0.0.0/4 (Multicast)
  if (o1 >= 224 && o1 <= 239) return true

  // 240.0.0.0/4 (Reserved / Class E)
  if (o1 >= 240) return true

  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const cleanIp = ip.replace(/^\[|\]$/g, '').toLowerCase()

  // Loopback ::1
  if (cleanIp === '::1' || cleanIp === '0000:0000:0000:0000:0000:0000:0000:0001') return true

  // Unspecified ::
  if (cleanIp === '::' || cleanIp === '0000:0000:0000:0000:0000:0000:0000:0000') return true

  // Link-local: fe80::/10
  if (cleanIp.startsWith('fe8') || cleanIp.startsWith('fe9') || cleanIp.startsWith('fea') || cleanIp.startsWith('feb')) return true

  // Unique Local Address (ULA): fc00::/7
  if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) return true

  // Multicast: ff00::/8
  if (cleanIp.startsWith('ff')) return true

  return false
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    let urlToParse = urlStr
    if (!/^https?:\/\//i.test(urlStr)) {
      urlToParse = 'http://' + urlStr
    }

    const parsedUrl = new URL(urlToParse)

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname.toLowerCase()

    // Block cloud metadata IPs & standard names unconditionally
    if (
      hostname === '169.254.169.254' ||
      hostname.includes('metadata') ||
      hostname === 'instance-data'
    ) {
      return false
    }

    if (process.env.NODE_ENV === 'test') {
      return true
    }

    if (hostname === 'localhost') {
      return false
    }

    let ip: string
    try {
      const lookupResult = await lookupPromise(parsedUrl.hostname)
      ip = lookupResult.address
    } catch {
      return true
    }

    if (ip.includes(':')) {
      if (isPrivateIPv6(ip)) return false
    } else {
      if (isPrivateIPv4(ip)) return false
    }

    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!await isSafeUrl(url)) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
