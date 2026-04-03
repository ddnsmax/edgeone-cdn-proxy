const SECRET_KEY = 'YOUR_CUSTOM_PASSWORD_HERE'; // 请修改为你自己的复杂密钥，并与 Cloudflare Worker 或Cloudflare Pages中的 SECRET_KEY 保持完全一致

export default onRequest;

function resolveKvBinding(context) {
  const envKv = context && context.env && context.env.PROXY_KV;
  if (envKv) return envKv;
  const globalKv = globalThis && globalThis.PROXY_KV;
  if (globalKv) return globalKv;
  try {
    if (typeof PROXY_KV !== 'undefined' && PROXY_KV) return PROXY_KV;
  } catch (e) {}
  return null;
}

export async function onRequest(context) {
  try {
    return await handleRequest(context);
  } catch (error) {
    return new Response(`脚本异常：${error?.stack || error?.message || error}`, {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache' },
    });
  }
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateSalt() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function handleRequest(context) {
  const { request } = context;
  const kv = resolveKvBinding(context);
  const url = new URL(request.url);

  if (url.pathname === '/health') {
    return textResponse('edge-functions-ok');
  }
  if (url.pathname === '/kvcheck') {
    let byBare = false;
    try {
      byBare = typeof PROXY_KV !== 'undefined' && !!PROXY_KV;
    } catch (e) {}
    return jsonResponse({
      byEnv: !!(context && context.env && context.env.PROXY_KV),
      byGlobalThis: !!(globalThis && globalThis.PROXY_KV),
      byBare,
    });
  }

  if (!kv) {
    return textResponse('未绑定 KV。请在 EdgeOne Pages 项目中绑定 KV 命名空间，并将变量名设置为 PROXY_KV。', 500);
  }

  let config = withConfigDefaults(await getConfig(kv));
  config = await migrateLegacyIfNeeded(kv, config, url.hostname);

  const adminPath = normalizePath(config.admin_path || '/admin');
  const mainSiteHost = normalizeHost(config.main_site_host || url.hostname);
  const requestHost = normalizeHost(url.hostname);
  config.admin_path = adminPath;
  config.main_site_host = mainSiteHost;

  if (!config.initialized) {
    if (request.method === 'POST') {
      const form = await request.formData();
      const account = String(form.get('admin_account') || '').trim();
      const password = String(form.get('admin_password') || '').trim();
      const salt = generateSalt();
      const hash = await sha256(password + salt);

      const nextConfig = withConfigDefaults({
        ...config,
        initialized: 1,
        admin_account: account,
        admin_password_hash: hash,
        admin_password_salt: salt,
        admin_path: normalizePath(form.get('admin_path') || '/admin'),
        main_site_host: normalizeHost(form.get('main_site_host') || requestHost),
        decoy_title: String(form.get('decoy_title') || '夏威夷定制假期').trim() || '夏威夷定制假期',
        decoy_subtitle: String(form.get('decoy_subtitle') || '逃离喧嚣，沉浸于阿罗哈的温柔海风').trim() || '逃离喧嚣，沉浸于阿罗哈的温柔海风',
        decoy_intro: String(form.get('decoy_intro') || '专注夏威夷多岛屿定制深度游，为您安排观鲸、直升机环岛、火山探险与奢华海景酒店，打造独一无二的波利尼西亚风情之旅。').trim() || '专注夏威夷多岛屿定制深度游',
      });
      await saveConfig(kv, nextConfig);
      await setProxyIds(kv, []);
      return redirect(`${url.protocol}//${nextConfig.main_site_host}${nextConfig.admin_path}`);
    }
    return htmlResponse(getInitHtml(requestHost));
  }

  if (url.pathname.startsWith(adminPath)) {
    if (requestHost !== mainSiteHost) return notFound();
    return await handleAdminRequest({ context, kv, config, url, requestHost });
  }

  if (requestHost === mainSiteHost) {
    return htmlResponse(getDecoyHtml(config));
  }

  const proxy = await getProxyByBindDomain(kv, requestHost);
  if (!proxy || Number(proxy.enabled) !== 1) return notFound();
  return await proxyRequest(request, proxy, requestHost, config, kv);
}

async function handleAdminRequest({ context, kv, config, url, requestHost }) {
  const { request } = context;
  const adminPath = config.admin_path;
  const loginPath = `${adminPath}/login`;
  const logoutPath = `${adminPath}/logout`;

  let isLoggedIn = false;
  const loginToken = getCookie(request.headers.get('Cookie') || '', 'proxy_login');

  if (loginToken) {
    try {
      const decoded = decodeBase64(loginToken);
      const parts = decoded.split('|');
      if (parts.length === 3) {
        const [tAccount, tExpire, tSign] = parts;
        if (Date.now() <= parseInt(tExpire, 10)) {
          const expectedSign = await sha256(tAccount + '|' + tExpire + '|' + SECRET_KEY);
          if (tSign === expectedSign && tAccount === config.admin_account) {
            isLoggedIn = true;
          }
        }
      }
    } catch (e) {}
  }

  if (url.pathname === logoutPath) {
    return new Response('', {
      status: 302,
      headers: {
        Location: `${url.protocol}//${config.main_site_host}${loginPath}`,
        'Set-Cookie': 'proxy_login=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
      },
    });
  }

  if (!isLoggedIn) {
    if (url.pathname === loginPath) {
      if (request.method === 'POST') {
        const form = await request.formData();
        const account = String(form.get('account') || '').trim();
        const password = String(form.get('password') || '').trim();
        const calculatedHash = await sha256(password + (config.admin_password_salt || ''));
        
        if (account === config.admin_account && calculatedHash === config.admin_password_hash) {
          const expire = Date.now() + 12 * 60 * 60 * 1000;
          const sign = await sha256(account + '|' + expire + '|' + SECRET_KEY);
          const token = encodeBase64(account + '|' + expire + '|' + sign);
          return new Response('', {
            status: 302,
            headers: {
              'Location': `${url.protocol}//${config.main_site_host}${adminPath}`,
              'Set-Cookie': `proxy_login=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`
            }
          });
        } else {
          return htmlResponse(getAuthHtml(adminPath, '账号或密码错误或已失效'));
        }
      }
      return htmlResponse(getAuthHtml(adminPath, ''));
    }
    return redirect(`${url.protocol}//${config.main_site_host}${loginPath}`);
  }

  const editProxyId = String(url.searchParams.get('edit_proxy') || '').trim();
  const editingProxy = editProxyId ? await getProxyById(kv, editProxyId) : null;
  const editNodeId = String(url.searchParams.get('edit_node') || '').trim();
  const editingNode = editNodeId ? (config.download_nodes || []).find(n => n.id === editNodeId) : null;

  if (request.method === 'POST') {
    const form = await request.formData();
    const action = String(form.get('action') || '').trim();

    if (action === 'update_base') {
      const newAdminPath = normalizePath(form.get('new_admin_path') || config.admin_path);
      const newMainHost = normalizeHost(form.get('main_site_host') || config.main_site_host);
      const newAccount = String(form.get('admin_account') || config.admin_account).trim();
      const newPassword = String(form.get('admin_password') || '').trim();

      let nextHash = config.admin_password_hash;
      let nextSalt = config.admin_password_salt;
      let pwdChanged = false;

      if (newPassword !== '') {
        nextSalt = generateSalt();
        nextHash = await sha256(newPassword + nextSalt);
        pwdChanged = true;
      }

      const nextConfig = withConfigDefaults({
        ...config,
        admin_path: newAdminPath,
        main_site_host: newMainHost || config.main_site_host,
        admin_account: newAccount,
        admin_password_hash: nextHash,
        admin_password_salt: nextSalt,
        decoy_title: String(form.get('decoy_title') || config.decoy_title).trim() || config.decoy_title,
        decoy_subtitle: String(form.get('decoy_subtitle') || config.decoy_subtitle).trim() || config.decoy_subtitle,
        decoy_intro: String(form.get('decoy_intro') || config.decoy_intro).trim() || config.decoy_intro,
      });

      const conflictProxy = await getProxyByBindDomain(kv, nextConfig.main_site_host);
      if (conflictProxy) {
        return htmlResponse(getAdminHtml(nextConfig, await listProxies(kv), editingProxy, editingNode, '主网站域名不能与任何反代绑定域名重复，请先修改或删除对应反代。'));
      }

      await saveConfig(kv, nextConfig);

      let redirectHeaders = new Headers();
      if (newAccount !== config.admin_account || pwdChanged) {
        redirectHeaders.set('Set-Cookie', 'proxy_login=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
        redirectHeaders.set('Location', `${url.protocol}//${nextConfig.main_site_host}${nextConfig.admin_path}/login`);
      } else if (newMainHost !== requestHost || newAdminPath !== config.admin_path) {
        redirectHeaders.set('Location', `${url.protocol}//${nextConfig.main_site_host}${nextConfig.admin_path}`);
      } else {
        redirectHeaders.set('Location', `${url.protocol}//${config.main_site_host}${config.admin_path}`);
      }

      return new Response('', { status: 302, headers: redirectHeaders });
    }

    if (action === 'save_download_node') {
      const nodeId = String(form.get('node_id') || '').trim();
      const remark = String(form.get('node_remark') || '').trim() || '未命名节点';
      let wUrl = String(form.get('node_url') || '').trim();
      if (wUrl && !/^https?:\/\//i.test(wUrl)) wUrl = 'https://' + wUrl;

      if (!wUrl) {
        return htmlResponse(getAdminHtml(config, await listProxies(kv), editingProxy, editingNode, '请填写节点地址。'));
      }

      try {
         const target = 'test';
         const expire = Date.now() + 60000;
         const sign = await generateSign(target, expire, SECRET_KEY);
         const testUrl = new URL(wUrl);
         testUrl.searchParams.set('target', encodeBase64(target));
         testUrl.searchParams.set('expire', expire);
         testUrl.searchParams.set('sign', sign);
         const res = await fetch(testUrl.toString());
         if (res.status === 200 && (await res.text()) === 'ok') {
            if (!config.download_nodes) config.download_nodes = [];
            if (nodeId) {
              const idx = config.download_nodes.findIndex(n => n.id === nodeId);
              if (idx >= 0) {
                config.download_nodes[idx].remark = remark;
                config.download_nodes[idx].url = wUrl;
              }
            } else {
              config.download_nodes.push({ id: Date.now().toString(), remark, url: wUrl, enabled: 1 });
            }
            await saveConfig(kv, config);
            return redirect(`${url.protocol}//${config.main_site_host}${config.admin_path}#node`);
         }
         return htmlResponse(getAdminHtml(config, await listProxies(kv), editingProxy, editingNode, '测试失败：节点响应异常或密钥不匹配。'));
      } catch(e) {
         return htmlResponse(getAdminHtml(config, await listProxies(kv), editingProxy, editingNode, `测试失败：无法连接到节点 (${e.message})`));
      }
    }

    if (action === 'delete_download_node') {
      const nodeId = String(form.get('node_id') || '').trim();
      if (config.download_nodes) {
        config.download_nodes = config.download_nodes.filter(n => n.id !== nodeId);
        await saveConfig(kv, config);
      }
      return redirect(`${url.protocol}//${config.main_site_host}${config.admin_path}#node`);
    }

    if (action === 'toggle_download_node') {
      const nodeId = String(form.get('node_id') || '').trim();
      if (config.download_nodes) {
        const idx = config.download_nodes.findIndex(n => n.id === nodeId);
        if (idx >= 0) {
          config.download_nodes[idx].enabled = config.download_nodes[idx].enabled === 0 ? 1 : 0;
          await saveConfig(kv, config);
        }
      }
      return redirect(`${url.protocol}//${config.main_site_host}${config.admin_path}#node`);
    }

    if (action === 'save_proxy') {
      const proxyId = String(form.get('proxy_id') || '').trim();
      const name = String(form.get('name') || '').trim() || '未命名反代';
      const bindDomain = normalizeHost(form.get('bind_domain') || '');
      const targetDomain = normalizeHost(form.get('target_domain') || '');
      
      let httpPort = parseInt(String(form.get('http_port') || ''), 10) || 80;
      let httpsPort = parseInt(String(form.get('https_port') || ''), 10) || 443;
      const proxyMode = String(form.get('proxy_mode') || 'auto');
      
      if (proxyMode === 'http_only') httpsPort = 0;
      else if (proxyMode === 'https_only') httpPort = 0;

      const enabled = form.get('enabled') ? 1 : 0;
      const cacheEnabled = form.get('cache_enabled') ? 1 : 0;

      if (!bindDomain || !targetDomain) {
        return htmlResponse(getAdminHtml(config, await listProxies(kv), editingProxy, editingNode, '请填写绑定域名和源站域名。'));
      }
      if (bindDomain === config.main_site_host) {
        return htmlResponse(getAdminHtml(config, await listProxies(kv), editingProxy, editingNode, '绑定域名不能和主网站域名相同。'));
      }
      const existing = await getProxyByBindDomain(kv, bindDomain);
      if (existing && String(existing.id) !== String(proxyId || '')) {
        return htmlResponse(getAdminHtml(config, await listProxies(kv), editingProxy, editingNode, '该绑定域名已经存在反代配置，一个域名只能绑定一个反代。'));
      }

      const now = new Date().toISOString();
      const current = proxyId ? await getProxyById(kv, proxyId) : null;
      const proxy = {
        id: proxyId || await nextProxyId(kv),
        name, bind_domain: bindDomain, target_domain: targetDomain,
        http_port: httpPort, https_port: httpsPort, proxy_mode: proxyMode,
        cache_enabled: cacheEnabled, enabled,
        create_time: current?.create_time || now, update_time: now,
      };
      await putProxy(kv, proxy, current);
      return redirect(`${url.protocol}//${config.main_site_host}${config.admin_path}#proxy`);
    }

    if (action === 'delete_proxy') {
      const proxyId = String(form.get('proxy_id') || '').trim();
      const proxy = proxyId ? await getProxyById(kv, proxyId) : null;
      if (proxy) await deleteProxy(kv, proxy);
      return redirect(`${url.protocol}//${config.main_site_host}${config.admin_path}#proxy`);
    }

    if (action === 'toggle_proxy') {
      const proxyId = String(form.get('proxy_id') || '').trim();
      const proxy = proxyId ? await getProxyById(kv, proxyId) : null;
      if (proxy) {
        proxy.enabled = Number(proxy.enabled) === 1 ? 0 : 1;
        proxy.update_time = new Date().toISOString();
        await putProxy(kv, proxy, null);
      }
      return redirect(`${url.protocol}//${config.main_site_host}${config.admin_path}#proxy`);
    }
  }

  const proxyList = await listProxies(kv);
  return htmlResponse(getAdminHtml(config, proxyList, editingProxy, editingNode, ''));
}

async function generateSign(target, expire, secret) {
  const data = new TextEncoder().encode(`${target}|${expire}|${secret}`);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function proxyRequest(request, proxy, requestHost, config, kv) {
  const candidates = [];
  if (proxy.proxy_mode === 'https_only') {
    if (!proxy.https_port) throw new Error('HTTPS端口未配置');
    candidates.push({ protocol: 'https:', port: proxy.https_port });
  } else if (proxy.proxy_mode === 'http_only') {
    if (!proxy.http_port) throw new Error('HTTP端口未配置');
    candidates.push({ protocol: 'http:', port: proxy.http_port });
  } else {
    if (proxy.https_port) candidates.push({ protocol: 'https:', port: proxy.https_port });
    if (proxy.http_port) candidates.push({ protocol: 'http:', port: proxy.http_port });
    if (!candidates.length) throw new Error('auto模式需至少配置一个端口');
  }

  let lastError = null;
  for (const target of candidates) {
    try {
      const targetUrl = new URL(request.url);
      targetUrl.protocol = target.protocol;
      targetUrl.hostname = proxy.target_domain;
      targetUrl.port = shouldOmitPort(target.protocol, target.port) ? '' : String(target.port);
      
      const hostHeader = formatHostHeader(proxy.target_domain, target.protocol, target.port);
      const upstreamRequest = new Request(targetUrl.toString(), {
        method: request.method,
        headers: buildProxyHeaders(request, targetUrl, hostHeader, requestHost),
        body: canHaveBody(request.method) ? request.body : undefined,
        redirect: 'manual',
      });
      
      if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
        return await fetch(upstreamRequest);
      }

      const upstreamResponse = await fetch(upstreamRequest);

      if (['GET', 'HEAD'].includes(request.method.toUpperCase()) && config.download_nodes && config.download_nodes.length > 0) {
        let totalSize = 0;
        let hasSize = false;
        
        const contentRange = upstreamResponse.headers.get('Content-Range');
        if (contentRange) {
          const match = contentRange.match(/\/(\d+)/);
          if (match) { totalSize = parseInt(match[1], 10); hasSize = true; }
        } else {
          const contentLength = upstreamResponse.headers.get('Content-Length');
          if (contentLength) { totalSize = parseInt(contentLength, 10); hasSize = true; }
        }

        const cd = String(upstreamResponse.headers.get('Content-Disposition') || '').toLowerCase();
        const isAttachment = cd.includes('attachment');
        
        const sfd = String(request.headers.get('Sec-Fetch-Dest') || '').toLowerCase();
        const isMediaFetch = ['video', 'audio', 'image', 'track'].includes(sfd);
        
        const contentType = String(upstreamResponse.headers.get('Content-Type') || '').toLowerCase();
        const isTextLike = contentType.includes('text/html') || contentType.includes('application/json') || contentType.includes('text/xml') || contentType.includes('application/xml') || contentType.includes('text/plain') || contentType.includes('text/css') || contentType.includes('application/javascript');

        let routeToWorker = false;
        
        if (!isMediaFetch && !isTextLike) {
          if (hasSize && totalSize > 20971520) {
            routeToWorker = true;
          } else if (!hasSize) {
            routeToWorker = true;
          }
        } else if (isAttachment) {
          if (hasSize && totalSize > 20971520) {
            routeToWorker = true;
          } else if (!hasSize) {
            routeToWorker = true;
          }
        }

        if (routeToWorker) {
           const activeNodes = (config.download_nodes || []).filter(n => n.enabled !== 0);
           if (activeNodes.length > 0) {
             let currentIndex = 0;
             if (kv) {
               let lastIdx = parseInt(await kv.get('meta_last_node_index') || '-1', 10);
               if (Number.isNaN(lastIdx)) lastIdx = -1;
               currentIndex = (lastIdx + 1) % activeNodes.length;
               await kv.put('meta_last_node_index', String(currentIndex));
             }
             const targetNode = activeNodes[currentIndex];
             const expire = Date.now() + 1000 * 60 * 60 * 24;
             const targetStr = targetUrl.toString();
             const sign = await generateSign(targetStr, expire, SECRET_KEY);
             const wUrl = new URL(targetNode.url);
             wUrl.searchParams.set('target', encodeBase64(targetStr));
             wUrl.searchParams.set('expire', expire);
             wUrl.searchParams.set('sign', sign);
             
             const reqCookie = request.headers.get('Cookie');
             const reqAuth = request.headers.get('Authorization');
             const reqReferer = request.headers.get('Referer');
             if (reqCookie) wUrl.searchParams.set('c', reqCookie);
             if (reqAuth) wUrl.searchParams.set('a', reqAuth);
             if (reqReferer) wUrl.searchParams.set('r', reqReferer);

             const redirectHeaders = new Headers();
             redirectHeaders.set('Location', wUrl.toString());
             rewriteCorsHeaders(redirectHeaders, request);
             return new Response('', { status: 302, headers: redirectHeaders });
           }
        }
      }

      return await handleProxyResponse(upstreamResponse, proxy, requestHost, request);
    } catch (error) {
      lastError = error;
    }
  }
  return textResponse(`反代请求失败：${lastError?.message || lastError || '未知错误'}`, 502);
}

function canHaveBody(method) {
  return !['GET', 'HEAD'].includes(String(method || '').toUpperCase());
}

function shouldOmitPort(protocol, port) {
  return (protocol === 'https:' && Number(port) === 443) || (protocol === 'http:' && Number(port) === 80);
}

function formatHostHeader(host, protocol, port) {
  return shouldOmitPort(protocol, port) ? host : `${host}:${port}`;
}

function buildProxyHeaders(request, targetUrl, targetHost, originalHost) {
  const h = new Headers(request.headers);
  const originalUrl = new URL(request.url);
  h.set('Host', targetHost);
  h.set('X-Forwarded-Host', originalHost);
  h.set('X-Forwarded-Proto', originalUrl.protocol.replace(':', ''));
  
  let clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For');
  if (clientIp) clientIp = clientIp.split(',')[0].trim();
  else clientIp = '127.0.0.1';
  h.set('X-Real-IP', clientIp);
  h.set('X-Forwarded-For', clientIp);

  h.delete('Content-Length');
  h.delete('Accept-Encoding');

  const origin = h.get('Origin');
  if (origin) {
    try {
      const u = new URL(origin);
      u.protocol = targetUrl.protocol;
      u.hostname = targetUrl.hostname;
      u.port = targetUrl.port;
      h.set('Origin', u.origin);
    } catch (e) {}
  }

  const referer = h.get('Referer');
  if (referer) {
    try {
      const u = new URL(referer);
      if (normalizeHost(u.hostname) === normalizeHost(originalHost)) {
        u.protocol = targetUrl.protocol;
        u.hostname = targetUrl.hostname;
        u.port = targetUrl.port;
        h.set('Referer', u.toString());
      }
    } catch (e) {}
  }

  return h;
}

async function handleProxyResponse(response, proxy, requestHost, request) {
  const contentType = response.headers.get('Content-Type') || '';
  const requestUrlObj = new URL(request.url);
  
  const isTextLike = contentType.includes('text/html') || contentType.includes('application/json') || contentType.includes('text/xml') || contentType.includes('application/xml');

  let outgoing;
  if (isTextLike) {
    let content = await response.text();
    content = replaceDomainRefs(content, proxy.target_domain, requestHost, proxy.https_port, proxy.http_port);
    outgoing = new Response(content, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    });
    outgoing.headers.delete('Content-Encoding');
    outgoing.headers.delete('Content-Length');
    outgoing.headers.delete('Transfer-Encoding');
    outgoing.headers.delete('ETag');
  } else {
    outgoing = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    });
  }

  rewriteLocationHeader(outgoing.headers, proxy.target_domain, requestHost, request.url);
  rewriteSetCookieHeaders(outgoing.headers, proxy.target_domain, requestHost, request.url);
  rewriteCorsHeaders(outgoing.headers, request);

  const isStaticAsset = /\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|mp4|webm|webp)(\?.*)?$/i.test(requestUrlObj.pathname) ||
                        contentType.includes('image/') ||
                        contentType.includes('font/') ||
                        contentType.includes('video/') ||
                        contentType.includes('audio/') ||
                        contentType.includes('text/css') ||
                        contentType.includes('application/javascript');

  if (Number(proxy.cache_enabled) === 1 && isStaticAsset && !isTextLike) {
    outgoing.headers.set('Cache-Control', 'public, max-age=604800, s-maxage=604800');
    outgoing.headers.delete('Pragma');
    outgoing.headers.delete('Expires');
  } else {
    outgoing.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    outgoing.headers.set('Pragma', 'no-cache');
    outgoing.headers.set('Expires', '0');
  }

  outgoing.headers.delete('X-Frame-Options');
  outgoing.headers.delete('Frame-Options');
  outgoing.headers.delete('Content-Security-Policy');
  outgoing.headers.delete('Content-Security-Policy-Report-Only');
  outgoing.headers.delete('Clear-Site-Data');
  if (!outgoing.headers.get('Referrer-Policy')) {
    outgoing.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  }
  return outgoing;
}

function rewriteLocationHeader(headers, targetDomain, requestHost, requestUrl) {
  const location = headers.get('Location');
  if (!location) return;
  try {
    const proxyUrl = new URL(requestUrl);
    const loc = new URL(location, proxyUrl.origin);
    if (normalizeHost(loc.hostname) === normalizeHost(targetDomain) || loc.hostname === 'localhost' || loc.hostname === '127.0.0.1') {
      loc.hostname = proxyUrl.hostname;
      loc.protocol = proxyUrl.protocol; 
      if (proxyUrl.protocol === 'https:' || proxyUrl.protocol === 'http:') {
        loc.port = proxyUrl.port; 
      }
      headers.set('Location', loc.toString());
    }
  } catch (e) {}
}

function rewriteSetCookieHeaders(headers, targetDomain, requestHost, requestUrl) {
  const raw = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  const all = raw.length ? raw : (headers.get('Set-Cookie') ? splitSetCookieHeader(headers.get('Set-Cookie')) : []);
  if (!all.length) return;
  headers.delete('Set-Cookie');
  
  const isHttps = new URL(requestUrl).protocol === 'https:';

  for (const line of all) {
    let cookie = String(line || '');
    cookie = cookie.replace(/;\s*Domain=[^;]+/ig, '');
    if (isHttps && !/;\s*Secure/i.test(cookie)) {
      cookie += '; Secure';
    }
    cookie = cookie.replace(/;\s*SameSite=Strict/ig, '; SameSite=Lax');
    headers.append('Set-Cookie', cookie);
  }
}

function splitSetCookieHeader(header) {
  const parts = [];
  let current = '';
  let inExpires = false;
  for (let i = 0; i < header.length; i++) {
    const ch = header[i];
    const next = header.slice(i, i + 8).toLowerCase();
    if (next === 'expires=') inExpires = true;
    if (ch === ',' && !inExpires) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    if (inExpires && ch === ';') inExpires = false;
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function rewriteCorsHeaders(headers, request) {
  const reqOrigin = request.headers.get('Origin');
  const allowedOrigin = reqOrigin || new URL(request.url).origin;
  headers.set('Access-Control-Allow-Origin', allowedOrigin);
  headers.set('Vary', appendVary(headers.get('Vary'), 'Origin'));
  headers.set('Access-Control-Allow-Credentials', 'true');
  const reqMethod = request.headers.get('Access-Control-Request-Method');
  const reqHeaders = request.headers.get('Access-Control-Request-Headers');
  if (reqMethod) headers.set('Access-Control-Allow-Methods', reqMethod + ', GET, POST, PUT, PATCH, DELETE, OPTIONS');
  if (reqHeaders) headers.set('Access-Control-Allow-Headers', reqHeaders);
}

function appendVary(current, name) {
  const values = String(current || '').split(',').map(v => v.trim()).filter(Boolean);
  if (!values.includes(name)) values.push(name);
  return values.join(', ');
}

function replaceDomainRefs(content, targetDomain, bindDomain, httpsPort, httpPort) {
  const escapedTarget = escapeRegExp(targetDomain);
  let out = String(content || '');
  if (httpsPort) out = out.replace(new RegExp(`https://${escapedTarget}:${httpsPort}`, 'g'), `https://${bindDomain}`);
  if (httpPort) out = out.replace(new RegExp(`http://${escapedTarget}:${httpPort}`, 'g'), `https://${bindDomain}`);
  out = out.replace(new RegExp(`https://${escapedTarget}`, 'g'), `https://${bindDomain}`);
  out = out.replace(new RegExp(`http://${escapedTarget}`, 'g'), `https://${bindDomain}`);
  out = out.replace(new RegExp(`//${escapedTarget}`, 'g'), `//${bindDomain}`);
  out = out.replace(new RegExp(`https:\\/\\/${escapedTarget}`, 'g'), `https:\\/\\/${bindDomain}`);
  out = out.replace(new RegExp(`http:\\/\\/${escapedTarget}`, 'g'), `https:\\/\\/${bindDomain}`);
  return out;
}

function escapeRegExp(input) {
  return String(input || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function withConfigDefaults(config) {
  return {
    initialized: 0,
    admin_path: '/admin',
    main_site_host: '',
    admin_account: '',
    admin_password_hash: '',
    admin_password_salt: '',
    decoy_title: '夏威夷定制假期',
    decoy_subtitle: '逃离喧嚣，沉浸于阿罗哈的温柔海风',
    decoy_intro: '专注夏威夷多岛屿定制深度游，为您安排观鲸、直升机环岛、火山探险与奢华海景酒店，打造独一无二的波利尼西亚风情之旅。',
    target_domain: '',
    worker_domain: '',
    http_port: 0,
    https_port: 0,
    proxy_mode: 'https_only',
    worker_node_url: '',
    download_nodes: [],
    ...config,
  };
}

function normalizePath(path) {
  let value = String(path || '').trim();
  if (!value) return '/';
  if (!value.startsWith('/')) value = '/' + value;
  if (value.length > 1 && value.endsWith('/')) value = value.slice(0, -1);
  return value;
}

function normalizeHost(host) {
  return String(host || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/:\d+$/, '').replace(/\/$/, '');
}

function toSafeKeyPart(value) {
  const bytes = new TextEncoder().encode(String(value ?? ''));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getConfigKey() { return 'config_main'; }
function getProxyKey(id) { return `proxy_${String(id)}`; }
function getProxyIdsKey() { return 'meta_proxy_ids'; }
function getProxyDomainIndexKey(host) { return `idx_proxy_domain_${toSafeKeyPart(normalizeHost(host))}`; }

async function getConfig(kv) { return await kv.get(getConfigKey(), { type: 'json' }); }
async function saveConfig(kv, config) { await kv.put(getConfigKey(), JSON.stringify(config)); }

async function nextNumber(kv, key) {
  const current = Number(await kv.get(key)) || 0;
  const next = current + 1;
  await kv.put(key, String(next));
  return String(next);
}
async function nextProxyId(kv) { return await nextNumber(kv, 'meta_next_proxy_id'); }

async function getProxyIds(kv) {
  const ids = await kv.get(getProxyIdsKey(), { type: 'json' });
  return Array.isArray(ids) ? ids.map(v => String(v)) : null;
}
async function setProxyIds(kv, ids) { await kv.put(getProxyIdsKey(), JSON.stringify(Array.from(new Set((ids || []).map(v => String(v)))))); }
async function getProxyById(kv, id) { return await kv.get(getProxyKey(id), { type: 'json' }); }
async function getProxyByBindDomain(kv, host) {
  const id = await kv.get(getProxyDomainIndexKey(host));
  return id ? await getProxyById(kv, id) : null;
}
async function putProxy(kv, proxy, oldProxy) {
  if (oldProxy && oldProxy.bind_domain && oldProxy.bind_domain !== proxy.bind_domain) {
    await kv.delete(getProxyDomainIndexKey(oldProxy.bind_domain));
  }
  await kv.put(getProxyKey(proxy.id), JSON.stringify(proxy));
  await kv.put(getProxyDomainIndexKey(proxy.bind_domain), String(proxy.id));
  let ids = await getProxyIds(kv);
  if (!ids) ids = [];
  if (!ids.includes(String(proxy.id))) ids.push(String(proxy.id));
  await setProxyIds(kv, ids);
}
async function deleteProxy(kv, proxy) {
  await kv.delete(getProxyKey(proxy.id));
  await kv.delete(getProxyDomainIndexKey(proxy.bind_domain));
  let ids = await getProxyIds(kv);
  if (!ids) ids = [];
  ids = ids.filter(id => String(id) !== String(proxy.id));
  await setProxyIds(kv, ids);
}
async function listProxies(kv) {
  const ids = (await getProxyIds(kv)) || [];
  const items = [];
  for (const id of ids) {
    const proxy = await getProxyById(kv, id);
    if (proxy) items.push(proxy);
  }
  items.sort((a, b) => new Date(b.update_time || b.create_time || 0).getTime() - new Date(a.update_time || a.create_time || 0).getTime());
  return items;
}

async function migrateLegacyIfNeeded(kv, config, currentHost) {
  let changed = false;
  if (!config.main_site_host) {
    config.main_site_host = normalizeHost(config.worker_domain || currentHost);
    changed = true;
  }
  if (config.worker_node_url && (!config.download_nodes || config.download_nodes.length === 0)) {
    config.download_nodes = [{
      id: Date.now().toString(),
      remark: '默认节点',
      url: config.worker_node_url,
      enabled: 1
    }];
    config.worker_node_url = '';
    changed = true;
  }
  const proxyIds = await getProxyIds(kv);
  if ((!proxyIds || proxyIds.length === 0) && config.target_domain && config.worker_domain) {
    const bindDomain = normalizeHost(config.worker_domain);
    if (bindDomain && bindDomain !== normalizeHost(config.main_site_host)) {
      const proxy = {
        id: await nextProxyId(kv),
        name: '迁移的历史反代',
        bind_domain: bindDomain,
        target_domain: normalizeHost(config.target_domain),
        http_port: config.http_port || 0,
        https_port: config.https_port || 0,
        proxy_mode: config.proxy_mode || 'https_only',
        cache_enabled: 0,
        enabled: 1,
        create_time: new Date().toISOString(),
        update_time: new Date().toISOString(),
      };
      await putProxy(kv, proxy, null);
    }
  }
  if (changed) await saveConfig(kv, config);
  return withConfigDefaults(config);
}

function getCookie(cookieHeader, name) {
  const cookies = String(cookieHeader || '').split(';').map(v => v.trim()).filter(Boolean);
  for (const item of cookies) {
    const idx = item.indexOf('=');
    const key = idx >= 0 ? item.slice(0, idx) : item;
    const value = idx >= 0 ? item.slice(idx + 1) : '';
    if (key === name) return value;
  }
  return '';
}

function encodeBase64(text) {
  const bytes = new TextEncoder().encode(String(text ?? ''));
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function decodeBase64(b64) {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for(let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch(e) { return ''; }
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    },
  });
}
function textResponse(text, status = 200) {
  return new Response(String(text ?? ''), { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
function redirect(location) { return new Response('', { status: 302, headers: { Location: location } }); }
function notFound() { return htmlResponse('<!doctype html><meta charset="utf-8"><title>404</title><div style="font-family:Arial;padding:40px;text-align:center;color:#334155"><h1>404</h1><p>页面不存在</p></div>', 404); }
function escapeHtml(input) {
  return String(input ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function layout(title, body, extraStyle = '', extraScript = '') {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${escapeHtml(title)}</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet"><style>
  *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#0f172a}
  .glass{background:rgba(255,255,255,.9);backdrop-filter:blur(10px);box-shadow:0 10px 35px rgba(15,23,42,.12);border:1px solid rgba(255,255,255,.5)}
  .btn{display:inline-flex;align-items:center;gap:.5rem;border:none;border-radius:10px;padding:.85rem 1.1rem;background:linear-gradient(135deg,#2563eb 0%,#3b82f6 100%);color:#fff;text-decoration:none;cursor:pointer}
  .btn-secondary{background:#0f172a}.btn-danger{background:#dc2626}.btn-ghost{background:#e2e8f0;color:#0f172a}
  .input,.select,textarea{width:100%;padding:.85rem 1rem;border:1px solid #dbe2ea;border-radius:10px;background:#f8fafc}
  .input:focus,.select:focus,textarea:focus{outline:none;border-color:#2563eb;background:#fff}
  .label{display:block;margin-bottom:.55rem;font-size:.92rem;font-weight:600;color:#334155}
  .alert{padding:.9rem 1rem;border-radius:10px;margin-bottom:1rem;font-weight:500;}
  .alert-error{background:#fee2e2;color:#b91c1c;border:1px solid #fecaca;}
  .alert-success{background:#dcfce7;color:#166534;border:1px solid #bbf7d0;}
  .muted{color:#64748b}.badge{display:inline-block;padding:.2rem .55rem;border-radius:999px;font-size:.74rem}.badge-ok{background:#dcfce7;color:#166534}.badge-off{background:#fee2e2;color:#991b1b}
  table{width:100%;border-collapse:collapse} th,td{padding:.8rem;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top}
  ${extraStyle}</style></head><body>${body}${extraScript}</body></html>`;
}

function getAuthHtml(adminPath, message) {
  return layout('本地系统登录', `
  <div style="min-height:100vh;background:linear-gradient(135deg,#eff6ff 0%,#dbeafe 100%);display:flex;align-items:center;justify-content:center;padding:20px;">
    <div class="glass" style="width:min(400px,100%);border-radius:18px;padding:30px;display:flex;flex-wrap:wrap;gap:30px;align-items:stretch;">
      <div style="flex:1;min-width:280px;display:flex;flex-direction:column;justify-content:center;">
        <h1 style="margin:0 0 8px;font-size:28px;"><i class="fa fa-shield" style="color:#2563eb"></i> 管理验证登录</h1>
        <p class="muted" style="margin:0 0 20px;">请输入您在初始化时设置的账号密码</p>
        ${message ? `<div class="alert alert-error">${escapeHtml(message)}</div>` : ''}
        <form method="POST" action="${escapeHtml(adminPath)}/login">
          <div style="margin-bottom:14px;"><label class="label">登录账号</label><input class="input" name="account" required></div>
          <div style="margin-bottom:18px;"><label class="label">登录密码</label><input type="password" class="input" name="password" required></div>
          <button class="btn" type="submit" style="width:100%;justify-content:center;"><i class="fa fa-sign-in"></i> 登录系统</button>
        </form>
      </div>
    </div>
  </div>`);
}

function getInitHtml(currentHost) {
  return layout('初始化本地系统', `
  <div style="min-height:100vh;background:linear-gradient(135deg,#eff6ff 0%,#e2e8f0 100%);display:flex;align-items:center;justify-content:center;padding:20px;">
    <div class="glass" style="width:min(760px,100%);border-radius:18px;padding:30px;">
      <h1 style="margin:0 0 8px;font-size:30px;">EdgeOne 反代节点初始化</h1>
      <p class="muted" style="margin:0 0 24px;">首次访问请设置您的本地管理员账号和基础配置。</p>
      <form method="POST">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
          <div><label class="label">管理员账号</label><input class="input" name="admin_account" placeholder="自定义后台登录账号" required></div>
          <div><label class="label">管理员密码</label><input type="password" class="input" name="admin_password" placeholder="自定义后台登录密码" required></div>
          <div><label class="label">主网站域名</label><input class="input" name="main_site_host" value="${escapeHtml(currentHost)}" required></div>
          <div><label class="label">后台访问路径</label><input class="input" name="admin_path" value="/admin" required></div>
          <div><label class="label">伪装站标题</label><input class="input" name="decoy_title" value="夏威夷定制假期"></div>
          <div><label class="label">伪装站副标题</label><input class="input" name="decoy_subtitle" value="逃离喧嚣，沉浸于阿罗哈的温柔海风"></div>
          <div style="grid-column:1 / -1;"><label class="label">伪装站介绍</label><textarea name="decoy_intro" rows="3">专注夏威夷多岛屿定制深度游，为您安排观鲸、直升机环岛、火山探险与奢华海景酒店，打造独一无二的波利尼西亚风情之旅。</textarea></div>
        </div>
        <div style="margin-top:20px;"><button class="btn" type="submit"><i class="fa fa-check-circle"></i> 完成初始化</button></div>
      </form>
    </div>
  </div>`);
}

function getAdminHtml(config, proxyList, editingProxy, editingNode, message) {
  const proxyRows = proxyList.length ? proxyList.map(item => `
    <tr>
      <td style="vertical-align:middle;">
        <div style="font-weight:600;color:#0f172a;">${escapeHtml(item.name || '')}</div>
        <div class="table-sub">ID：${escapeHtml(item.id)}</div>
      </td>
      <td style="vertical-align:middle;">${escapeHtml(item.bind_domain)}</td>
      <td style="vertical-align:middle;">
        <div>${escapeHtml(item.proxy_mode === 'auto' ? 'HTTP + HTTPS 自适应' : (item.proxy_mode === 'https_only' ? '仅 HTTPS' : '仅 HTTP'))}</div>
      </td>
      <td style="vertical-align:middle;">
        <form method="POST" style="margin:0;display:flex;align-items:center;">
          <input type="hidden" name="action" value="toggle_proxy">
          <input type="hidden" name="proxy_id" value="${escapeHtml(item.id)}">
          <button type="submit" style="border:none;background:transparent;padding:0;cursor:pointer;font-family:inherit;transition:all 0.2s;display:flex;align-items:center;" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">
            ${Number(item.enabled) === 1 ? '<span class="status-dot status-on" style="border:1px solid #86efac;box-shadow:0 2px 4px rgba(0,0,0,0.05);display:flex;align-items:center;gap:0.3rem;"><i class="fa fa-toggle-on" style="font-size:1.1rem;"></i> 已开启</span>' : '<span class="status-dot status-off" style="border:1px solid #fca5a5;box-shadow:0 2px 4px rgba(0,0,0,0.05);display:flex;align-items:center;gap:0.3rem;"><i class="fa fa-toggle-off" style="font-size:1.1rem;"></i> 已停用</span>'}
          </button>
        </form>
      </td>
      <td style="vertical-align:middle;">
        <div style="display:flex;align-items:center;gap:.5rem;">
          <a class="mini-btn mini-btn-edit" href="${config.admin_path}?edit_proxy=${encodeURIComponent(item.id)}#proxy" style="display:inline-flex;align-items:center;justify-content:center;">编辑</a>
          <form method="POST" onsubmit="return confirm('确定删除这个反代配置吗？')" style="margin:0;display:flex;align-items:center;">
            <input type="hidden" name="action" value="delete_proxy">
            <input type="hidden" name="proxy_id" value="${escapeHtml(item.id)}">
            <button class="mini-btn mini-btn-del" type="submit" style="display:inline-flex;align-items:center;justify-content:center;">删除</button>
          </form>
        </div>
      </td>
    </tr>`).join('') : '<tr><td colspan="5" class="empty-row">暂无反代配置</td></tr>';

  let proxyFormsHtml = '';
  if (editingProxy) {
      proxyFormsHtml = `
      <div class="content-card" id="edit-proxy-card">
        <div class="card-head-split">
          <h3 class="card-title"><i class="fa fa-edit"></i>编辑反代配置 (ID: ${escapeHtml(editingProxy.id)})</h3>
          <a class="submit-btn submit-btn-lite" href="${config.admin_path}#proxy">取消编辑 / 返回新增</a>
        </div>
        <form method="POST">
          <input type="hidden" name="action" value="save_proxy">
          <input type="hidden" name="proxy_id" value="${escapeHtml(editingProxy.id)}">
          <div class="form-grid form-grid-3">
            <div class="form-group"><label class="form-label">反代名称</label><input type="text" name="name" class="form-input" value="${escapeHtml(editingProxy.name || '')}"></div>
            <div class="form-group"><label class="form-label">绑定域名</label><input type="text" name="bind_domain" class="form-input" value="${escapeHtml(editingProxy.bind_domain || '')}" required></div>
            <div class="form-group"><label class="form-label">源站域名</label><input type="text" name="target_domain" class="form-input" value="${escapeHtml(editingProxy.target_domain || '')}" required></div>
          </div>
          <div class="form-grid form-grid-3">
            <div class="form-group"><label class="form-label">HTTP端口</label><input type="number" name="http_port" class="form-input" value="${editingProxy.http_port || ''}"></div>
            <div class="form-group"><label class="form-label">HTTPS端口</label><input type="number" name="https_port" class="form-input" value="${editingProxy.https_port || ''}"></div>
            <div class="form-group"><label class="form-label">反代模式</label><select name="proxy_mode" class="form-input"><option value="http_only" ${editingProxy.proxy_mode === 'http_only' ? 'selected' : ''}>仅 HTTP</option><option value="https_only" ${editingProxy.proxy_mode === 'https_only' ? 'selected' : ''}>仅 HTTPS</option><option value="auto" ${editingProxy.proxy_mode === 'auto' ? 'selected' : ''}>HTTP + HTTPS 自适应</option></select></div>
          </div>
          <div class="switch-row" style="margin-bottom:0;">
            <label class="switch-item"><input type="checkbox" name="enabled" ${Number(editingProxy.enabled) === 1 ? 'checked' : ''}><span>启用该反代</span></label>
            <label class="switch-item"><input type="checkbox" name="cache_enabled" ${Number(editingProxy.cache_enabled) === 1 ? 'checked' : ''}><span>开启静态缓存</span></label>
          </div>
          <button type="submit" class="submit-btn"><i class="fa fa-save"></i> 保存修改</button>
        </form>
      </div>`;
  } else {
      proxyFormsHtml = `
      <div style="margin-bottom: 1.5rem;" id="add-proxy-btn-wrap">
         <button type="button" class="submit-btn" onclick="document.getElementById('add-proxy-card').style.display='block';document.getElementById('add-proxy-btn-wrap').style.display='none';"><i class="fa fa-plus"></i> 新增反代配置</button>
      </div>
      <div class="content-card" id="add-proxy-card" style="display:none;">
        <div class="card-head-split">
          <h3 class="card-title"><i class="fa fa-plus-circle"></i>新增反代配置</h3>
          <button type="button" class="mini-btn mini-btn-gray" onclick="document.getElementById('add-proxy-card').style.display='none';document.getElementById('add-proxy-btn-wrap').style.display='block';">取消新增</button>
        </div>
        <form method="POST">
          <input type="hidden" name="action" value="save_proxy">
          <div class="form-grid form-grid-3">
            <div class="form-group"><label class="form-label">反代名称</label><input type="text" name="name" class="form-input" placeholder="例如：图床站"></div>
            <div class="form-group"><label class="form-label">绑定域名</label><input type="text" name="bind_domain" class="form-input" placeholder="例如：img.example.com" required></div>
            <div class="form-group"><label class="form-label">源站域名</label><input type="text" name="target_domain" class="form-input" placeholder="例如：source.example.com" required></div>
          </div>
          <div class="form-grid form-grid-3">
            <div class="form-group"><label class="form-label">HTTP端口</label><input type="number" name="http_port" class="form-input" value="80"></div>
            <div class="form-group"><label class="form-label">HTTPS端口</label><input type="number" name="https_port" class="form-input" value="443"></div>
            <div class="form-group"><label class="form-label">反代模式</label><select name="proxy_mode" class="form-input"><option value="http_only">仅 HTTP</option><option value="https_only">仅 HTTPS</option><option value="auto" selected>HTTP + HTTPS 自适应</option></select></div>
          </div>
          <div class="switch-row" style="margin-bottom:0;">
            <label class="switch-item"><input type="checkbox" name="enabled" checked><span>默认开启该反代</span></label>
            <label class="switch-item"><input type="checkbox" name="cache_enabled" checked><span>开启静态缓存</span></label>
          </div>
          <button type="submit" class="submit-btn"><i class="fa fa-save"></i> 立即添加</button>
        </form>
      </div>`;
  }

  const nodeColors = ['#3b82f6', '#10b981', '#8b5cf6', '#f43f5e', '#f59e0b', '#0ea5e9', '#ec4899', '#14b8a6'];
  const nodeRows = (config.download_nodes || []).length ? (config.download_nodes || []).map((item, idx) => `
    <tr>
      <td style="vertical-align:middle;">
        <div style="display:flex;align-items:center;gap:.6rem;">
          <span style="background:${nodeColors[idx % nodeColors.length]};color:#fff;border-radius:6px;padding:0.15rem 0.5rem;font-size:0.8rem;font-weight:bold;">${idx + 1}</span>
          <span style="font-weight:600;color:#0f172a;">${escapeHtml(item.remark || '')}</span>
        </div>
      </td>
      <td style="vertical-align:middle;">
        <form method="POST" style="margin:0;display:flex;align-items:center;">
          <input type="hidden" name="action" value="toggle_download_node">
          <input type="hidden" name="node_id" value="${escapeHtml(item.id)}">
          <button type="submit" style="border:none;background:transparent;padding:0;cursor:pointer;font-family:inherit;transition:all 0.2s;display:flex;align-items:center;" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">
            ${item.enabled !== 0 ? '<span class="status-dot status-on" style="border:1px solid #86efac;box-shadow:0 2px 4px rgba(0,0,0,0.05);display:flex;align-items:center;gap:.3rem;"><i class="fa fa-toggle-on" style="font-size:1.1rem;"></i> 已开启</span>' : '<span class="status-dot status-off" style="border:1px solid #fca5a5;box-shadow:0 2px 4px rgba(0,0,0,0.05);display:flex;align-items:center;gap:.3rem;"><i class="fa fa-toggle-off" style="font-size:1.1rem;"></i> 已暂停</span>'}
          </button>
        </form>
      </td>
      <td style="vertical-align:middle;">
        <div style="display:flex;align-items:center;gap:.5rem;">
          <a class="mini-btn mini-btn-edit" href="${config.admin_path}?edit_node=${encodeURIComponent(item.id)}#node" style="display:inline-flex;align-items:center;justify-content:center;">编辑</a>
          <form method="POST" onsubmit="return confirm('确定删除这个节点配置吗？')" style="margin:0;display:flex;align-items:center;">
            <input type="hidden" name="action" value="delete_download_node">
            <input type="hidden" name="node_id" value="${escapeHtml(item.id)}">
            <button class="mini-btn mini-btn-del" type="submit" style="display:inline-flex;align-items:center;justify-content:center;">删除</button>
          </form>
        </div>
      </td>
    </tr>`).join('') : '<tr><td colspan="3" class="empty-row">暂无节点配置</td></tr>';

  let nodeFormsHtml = '';
  if (editingNode) {
      nodeFormsHtml = `
      <div class="content-card" id="edit-node-card">
        <div class="card-head-split">
          <h3 class="card-title"><i class="fa fa-edit"></i>编辑下载节点</h3>
          <a class="submit-btn submit-btn-lite" href="${config.admin_path}#node">取消编辑 / 返回新增</a>
        </div>
        <form method="POST">
          <input type="hidden" name="action" value="save_download_node">
          <input type="hidden" name="node_id" value="${escapeHtml(editingNode.id)}">
          <div class="form-grid">
            <div class="form-group"><label class="form-label">备注</label><input type="text" name="node_remark" class="form-input" value="${escapeHtml(editingNode.remark || '')}" required></div>
            <div class="form-group"><label class="form-label">节点地址</label><input type="text" name="node_url" class="form-input" value="${escapeHtml(editingNode.url || '')}" required></div>
          </div>
          <button type="submit" class="submit-btn"><i class="fa fa-save"></i> 保存并测试联通性</button>
        </form>
      </div>`;
  } else {
      nodeFormsHtml = `
      <div style="margin-bottom: 1.5rem;" id="add-node-btn-wrap">
         <button type="button" class="submit-btn" onclick="document.getElementById('add-node-card').style.display='block';document.getElementById('add-node-btn-wrap').style.display='none';"><i class="fa fa-plus"></i> 新增下载节点</button>
      </div>
      <div class="content-card" id="add-node-card" style="display:none;">
        <div class="card-head-split">
          <h3 class="card-title"><i class="fa fa-plus-circle"></i>新增下载节点</h3>
          <button type="button" class="mini-btn mini-btn-gray" onclick="document.getElementById('add-node-card').style.display='none';document.getElementById('add-node-btn-wrap').style.display='block';">取消新增</button>
        </div>
        <form method="POST">
          <input type="hidden" name="action" value="save_download_node">
          <div class="form-grid">
            <div class="form-group"><label class="form-label">备注</label><input type="text" name="node_remark" class="form-input" placeholder="例如：美西节点1" required></div>
            <div class="form-group"><label class="form-label">节点地址</label><input type="text" name="node_url" class="form-input" placeholder="例如：https://dl.your-worker.workers.dev" required></div>
          </div>
          <button type="submit" class="submit-btn"><i class="fa fa-save"></i> 保存并测试联通性</button>
        </form>
      </div>`;
  }

  return layout('本地系统后台', `
  <div class="admin-shell">
    <aside class="sidebar">
      <div class="sidebar-header">
        <h2><i class="fa fa-cogs"></i><span>控制台</span></h2>
      </div>
      <div class="sidebar-menu">
        <div class="menu-item active" onclick="switchTab('base-tab', event)"><i class="fa fa-sliders"></i><span>基础配置</span></div>
        <div class="menu-item" onclick="switchTab('proxy-tab', event)"><i class="fa fa-cloud"></i><span>反代配置</span></div>
        <div class="menu-item" onclick="switchTab('node-tab', event)"><i class="fa fa-download"></i><span>下载节点</span></div>
      </div>
      <div class="sidebar-footer"><a href="${config.admin_path}/logout"><i class="fa fa-sign-out"></i> 安全退出</a></div>
    </aside>
    <main class="main-content">
      <div class="content-header">
        <h1>系统管理后台</h1>
        <div class="content-sub">当前节点主域：${escapeHtml(config.main_site_host)}</div>
      </div>
      ${message ? `<div class="alert ${message.includes('成功') ? 'alert-success' : 'alert-error'}">${escapeHtml(message)}</div>` : ''}

      <div id="base-tab" class="tab-content active">
        <div class="content-card">
          <h3 class="card-title"><i class="fa fa-sliders"></i> 基础访问与安全配置</h3>
          <form method="POST">
            <input type="hidden" name="action" value="update_base">
            <div class="form-grid">
              <div class="form-group"><label class="form-label">管理员账号</label><input type="text" name="admin_account" class="form-input" value="${escapeHtml(config.admin_account)}" required></div>
              <div class="form-group"><label class="form-label">管理员密码</label><input type="password" name="admin_password" class="form-input" placeholder="留空则不修改密码"></div>
              <div class="form-group"><label class="form-label">主网站域名</label><input type="text" name="main_site_host" class="form-input" value="${escapeHtml(config.main_site_host)}" required></div>
              <div class="form-group"><label class="form-label">后台访问路径</label><input type="text" name="new_admin_path" class="form-input" value="${escapeHtml(config.admin_path)}" required></div>
            </div>
            <p class="muted" style="margin-top:-10px;margin-bottom:15px;font-size:14px;">修改账号或密码后，需要重新登录。</p>
            <button type="submit" class="submit-btn"><i class="fa fa-save"></i> 保存核心配置</button>
          </form>
        </div>
        <div class="content-card">
          <h3 class="card-title"><i class="fa fa-globe"></i> 主网站展示配置</h3>
          <form method="POST">
            <input type="hidden" name="action" value="update_base">
            <input type="hidden" name="main_site_host" value="${escapeHtml(config.main_site_host)}">
            <input type="hidden" name="new_admin_path" value="${escapeHtml(config.admin_path)}">
            <div class="form-grid">
              <div class="form-group"><label class="form-label">站点标题</label><input type="text" name="decoy_title" class="form-input" value="${escapeHtml(config.decoy_title)}"></div>
              <div class="form-group"><label class="form-label">首页主标题</label><input type="text" name="decoy_subtitle" class="form-input" value="${escapeHtml(config.decoy_subtitle)}"></div>
            </div>
            <div class="form-group"><label class="form-label">站点介绍文案</label><textarea name="decoy_intro" rows="4" class="form-input">${escapeHtml(config.decoy_intro)}</textarea></div>
            <button type="submit" class="submit-btn"><i class="fa fa-save"></i> 保存展示文案</button>
          </form>
        </div>
      </div>

      <div id="proxy-tab" class="tab-content">
        ${proxyFormsHtml}
        <div class="content-card">
          <h3 class="card-title"><i class="fa fa-list"></i> 反代节点列表</h3>
          <div class="table-wrap">
            <table class="user-table">
              <thead>
                <tr><th>名称</th><th>绑定域名</th><th>模式</th><th>状态</th><th>操作</th></tr>
              </thead>
              <tbody>${proxyRows}</tbody>
            </table>
          </div>
        </div>
      </div>

      <div id="node-tab" class="tab-content">
        ${nodeFormsHtml}
        <div class="content-card">
          <h3 class="card-title"><i class="fa fa-list"></i> 下载节点列表</h3>
          <div class="table-wrap">
            <table class="user-table">
              <thead>
                <tr><th>序号/备注</th><th>状态</th><th>操作</th></tr>
              </thead>
              <tbody>${nodeRows}</tbody>
            </table>
          </div>
        </div>
      </div>
    </main>
  </div>`, `.admin-shell{background:#f8fafc;min-height:100vh;display:flex}.sidebar{width:250px;background:#0f172a;color:#f8fafc;min-height:100vh;padding:1.5rem 0;position:fixed;left:0;top:0}.sidebar-header{padding:0 1.5rem 1.2rem;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:1rem}.sidebar-header h2{font-size:1.2rem;font-weight:700;color:#fff;display:flex;align-items:center;margin:0}.sidebar-header h2 i{margin-right:.75rem;color:#38bdf8}.sidebar-sub{margin-top:.7rem;color:#94a3b8;font-size:.82rem;word-break:break-all}.sidebar-menu{padding:.5rem 0}.menu-item{padding:.875rem 1.5rem;display:flex;align-items:center;color:#94a3b8;text-decoration:none;transition:all .2s ease;cursor:pointer;border-left:3px solid transparent}.menu-item.active{background:#1e293b;color:#fff;border-left-color:#38bdf8}.menu-item:hover{background:#162235;color:#e2e8f0}.menu-item i{margin-right:.75rem;font-size:1rem;width:18px;text-align:center}.sidebar-footer{padding:1.2rem 1.5rem;border-top:1px solid rgba(255,255,255,.08);position:absolute;bottom:0;left:0;right:0}.sidebar-footer a{color:#cbd5e1;text-decoration:none}.main-content{margin-left:250px;flex:1;padding:2rem}.content-header{margin-bottom:1.5rem;padding-bottom:1rem;border-bottom:1px solid #e2e8f0}.content-header h1{font-size:1.8rem;font-weight:700;color:#0f172a;margin:0}.content-sub{margin-top:.5rem;color:#64748b}.content-card{background:#fff;border-radius:14px;box-shadow:0 10px 30px rgba(15,23,42,.06);padding:2rem;margin-bottom:1.5rem;overflow-x:auto}.card-title{font-size:1.25rem;font-weight:700;color:#1e293b;margin-bottom:1.4rem;display:flex;align-items:center}.card-title i{margin-right:.75rem;color:#2563eb}.card-head-split{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}.form-group{margin-bottom:1.2rem}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}.form-grid-3{grid-template-columns:repeat(3,minmax(0,1fr))}.form-label{display:block;margin-bottom:.65rem;font-weight:600;color:#334155;font-size:.95rem}.form-input{width:100%;padding:.875rem 1rem;border:1px solid #e2e8f0;border-radius:10px;font-size:.95rem;background:#f8fafc}.form-input:focus{outline:none;border-color:#2563eb;background:#fff}.switch-row{display:flex;align-items:center;gap:1rem;margin:1rem 0 1.5rem;flex-wrap:wrap}.switch-item{display:flex;align-items:center;gap:.55rem;color:#334155;font-weight:500}.switch-item input{width:1.1rem;height:1.1rem;accent-color:#2563eb}.submit-btn{display:inline-flex;align-items:center;gap:.45rem;padding:.875rem 1.35rem;background:linear-gradient(135deg,#2563eb 0%,#3b82f6 100%);color:#fff;border:none;border-radius:10px;cursor:pointer;text-decoration:none}.submit-btn-lite{background:#eff6ff;color:#1d4ed8}.tab-content{display:none}.tab-content.active{display:block}.table-wrap{overflow:auto}.user-table{width:100%;border-collapse:collapse;margin-top:0}.user-table th{padding:.8rem 1rem;text-align:left;background:#f1f5f9;font-weight:600;color:#334155;white-space:nowrap}.user-table td{padding:.9rem 1rem;color:#1e293b;vertical-align:top;border-bottom:1px solid #e5e7eb}.table-sub{font-size:.78rem;color:#64748b;margin-top:.3rem;word-break:break-all}.empty-row{text-align:center;color:#94a3b8;padding:1.4rem !important}.status-dot{display:inline-flex;align-items:center;gap:.4rem;padding:.25rem .7rem;border-radius:999px;font-size:.76rem;font-weight:600;transition:all 0.2s}.status-dot:hover{opacity:0.85;transform:scale(1.02)}.status-on{background:#dcfce7;color:#166534}.status-off{background:#fee2e2;color:#991b1b}.mini-input{padding:.45rem .6rem;border:1px solid #dbe2ea;border-radius:8px;background:#fff;min-width:110px}.mini-input-days{min-width:70px;width:70px}.mini-btn{padding:.42rem .68rem;border:none;border-radius:8px;color:#fff;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}.mini-btn-edit{background:#2563eb}.mini-btn-del{background:#dc2626}.mini-btn-gray{background:#64748b}@media (max-width:1080px){.form-grid-3,.form-grid{grid-template-columns:1fr}}@media (max-width:768px){.sidebar{width:80px;padding:1rem 0}.sidebar-header h2 span,.menu-item span,.sidebar-sub,.sidebar-footer{display:none}.menu-item{justify-content:center;padding:1rem}.menu-item i{margin-right:0;font-size:1.2rem}.main-content{margin-left:80px;padding:1.2rem}.content-card{padding:1.25rem}}`, `<script>
  (function(){
    const initialHash = window.location.hash ? window.location.hash.substring(1) : 'base';
    const targetTab = document.getElementById(initialHash + '-tab') ? initialHash + '-tab' : 'base-tab';
    switchTab(targetTab);
  })();
  function switchTab(tabId, event) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.menu-item').forEach(item => item.classList.remove('active'));
    const current = document.getElementById(tabId);
    if (current) current.classList.add('active');
    const pureId = tabId.replace('-tab', '');
    document.querySelectorAll('.menu-item').forEach(item => {
      const clickValue = item.getAttribute('onclick') || '';
      if (clickValue.includes(tabId)) item.classList.add('active');
    });
    if (event && event.currentTarget) {
      document.querySelectorAll('.menu-item').forEach(item => item.classList.remove('active'));
      event.currentTarget.classList.add('active');
    }
    window.history.replaceState(null, null, '#' + pureId);
  }
</script>`);
}

function getDecoyHtml(config) {
  const brand = escapeHtml(config.decoy_title || '夏威夷定制假期');
  const heroTitle = escapeHtml(config.decoy_subtitle || '逃离喧嚣，沉浸于阿罗哈的温柔海风');
  const intro = escapeHtml(config.decoy_intro || '专注夏威夷多岛屿定制深度游，为您安排观鲸、直升机环岛、火山探险与奢华海景酒店，打造独一无二的波利尼西亚风情之旅。');

  return layout(brand, `
  <div class="font-sans text-gray-800 bg-white min-h-screen">
    <nav class="absolute top-0 left-0 right-0 z-50 flex items-center justify-between px-6 md:px-12 py-6 text-white bg-gradient-to-b from-black/60 to-transparent">
        <div class="text-2xl font-bold tracking-wider flex items-center gap-2">
            <i class="fa fa-leaf"></i> ${brand}
        </div>
        <div class="hidden md:flex space-x-8 text-sm font-medium items-center">
            <a href="#" class="hover:text-blue-200 transition">首页推荐</a>
            <a href="#islands" class="hover:text-blue-200 transition">热门岛屿</a>
            <a href="#experiences" class="hover:text-blue-200 transition">深度体验</a>
            <a href="#contact" class="bg-white/20 hover:bg-white/30 px-5 py-2.5 rounded-full backdrop-blur-sm transition border border-white/30">定制咨询</a>
        </div>
    </nav>

    <header class="relative h-screen flex items-center justify-center overflow-hidden">
        <div class="absolute inset-0 z-0">
            <img src="https://images.unsplash.com/photo-1542259009477-d625272157b7?q=80&w=1920&auto=format&fit=crop" alt="Hawaii Beach" class="w-full h-full object-cover" />
            <div class="absolute inset-0 bg-black/40"></div>
        </div>
        <div class="relative z-10 text-center px-4 max-w-5xl mx-auto mt-16">
            <span class="inline-block py-1.5 px-4 rounded-full bg-white/10 backdrop-blur-md border border-white/20 text-white text-xs md:text-sm tracking-widest mb-6 uppercase">Aloha · Hawaii Exclusive Travel</span>
            <h1 class="text-5xl md:text-7xl lg:text-8xl font-extrabold text-white mb-6 leading-tight drop-shadow-2xl" style="text-shadow: 0 4px 20px rgba(0,0,0,0.5);">${heroTitle}</h1>
            <p class="text-lg md:text-xl text-gray-100 mb-10 leading-relaxed font-light drop-shadow-md max-w-3xl mx-auto">${intro}</p>
            <a href="#contact" class="inline-flex items-center justify-center bg-blue-600 hover:bg-blue-700 text-white font-semibold text-lg py-4 px-10 rounded-full transition duration-300 shadow-[0_8px_30px_rgb(37,99,235,0.4)] hover:shadow-[0_8px_30px_rgb(37,99,235,0.6)] transform hover:-translate-y-1">
                开启专属假日 <i class="fa fa-arrow-right ml-2"></i>
            </a>
        </div>
        
        <div class="absolute bottom-10 left-1/2 transform -translate-x-1/2 text-white/70 animate-bounce cursor-pointer">
            <a href="#islands"><i class="fa fa-angle-down text-4xl"></i></a>
        </div>
    </header>

    <section id="islands" class="py-24 px-4 md:px-8 max-w-7xl mx-auto">
        <div class="text-center mb-16">
            <span class="text-blue-600 font-bold tracking-wider uppercase text-sm mb-2 block">Destinations</span>
            <h2 class="text-3xl md:text-4xl font-extrabold text-gray-900 mb-4">探索夏威夷群岛</h2>
            <p class="text-gray-500 max-w-2xl mx-auto text-lg">每个岛屿都有其独特的灵魂，从繁华的威基基海滩到神秘的纳帕利海岸，为您精选最值得造访的目的地。</p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-10">
            <div class="group rounded-[2rem] overflow-hidden shadow-sm hover:shadow-2xl bg-white border border-gray-100 transition-all duration-500 cursor-pointer">
                <div class="relative h-72 overflow-hidden">
                    <img src="https://images.unsplash.com/photo-1572949645841-094f3a9c4c94?q=80&w=800&auto=format&fit=crop" alt="欧胡岛" class="w-full h-full object-cover transform group-hover:scale-110 transition duration-700">
                    <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent"></div>
                    <div class="absolute bottom-6 left-6">
                        <h3 class="text-3xl font-bold text-white mb-1">欧胡岛</h3>
                        <p class="text-white/80 text-sm">O'ahu · 聚会之地</p>
                    </div>
                </div>
                <div class="p-8">
                    <p class="text-gray-600 mb-6 leading-relaxed">夏威夷的“聚会之地”，这里有举世闻名的威基基海滩、历史悠久的珍珠港以及北海岸的冲浪圣地。</p>
                    <span class="inline-flex items-center text-blue-600 font-semibold group-hover:text-blue-700">查看路线 <i class="fa fa-angle-right ml-1 transition-transform group-hover:translate-x-1"></i></span>
                </div>
            </div>
            <div class="group rounded-[2rem] overflow-hidden shadow-sm hover:shadow-2xl bg-white border border-gray-100 transition-all duration-500 cursor-pointer">
                <div class="relative h-72 overflow-hidden">
                    <img src="https://images.unsplash.com/photo-1544644181-1484b3fdfc62?q=80&w=800&auto=format&fit=crop" alt="茂宜岛" class="w-full h-full object-cover transform group-hover:scale-110 transition duration-700">
                    <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent"></div>
                    <div class="absolute bottom-6 left-6">
                        <h3 class="text-3xl font-bold text-white mb-1">茂宜岛</h3>
                        <p class="text-white/80 text-sm">Maui · 山谷之岛</p>
                    </div>
                </div>
                <div class="p-8">
                    <p class="text-gray-600 mb-6 leading-relaxed">被誉为“山谷之岛”，哈雷阿卡拉火山口的日出与哈纳公路的绝美海岸线将让您感受到极致的自然浪漫。</p>
                    <span class="inline-flex items-center text-blue-600 font-semibold group-hover:text-blue-700">查看路线 <i class="fa fa-angle-right ml-1 transition-transform group-hover:translate-x-1"></i></span>
                </div>
            </div>
            <div class="group rounded-[2rem] overflow-hidden shadow-sm hover:shadow-2xl bg-white border border-gray-100 transition-all duration-500 cursor-pointer">
                <div class="relative h-72 overflow-hidden">
                    <img src="https://images.unsplash.com/photo-1600255821058-c4f89958d700?q=80&w=800&auto=format&fit=crop" alt="夏威夷大岛" class="w-full h-full object-cover transform group-hover:scale-110 transition duration-700">
                    <div class="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent"></div>
                    <div class="absolute bottom-6 left-6">
                        <h3 class="text-3xl font-bold text-white mb-1">大岛</h3>
                        <p class="text-white/80 text-sm">Big Island · 探险胜地</p>
                    </div>
                </div>
                <div class="p-8">
                    <p class="text-gray-600 mb-6 leading-relaxed">拥有令人敬畏的活火山、漆黑的沙滩以及繁星密布的夜空，是大自然力量与天文奇观的最佳展现地。</p>
                    <span class="inline-flex items-center text-blue-600 font-semibold group-hover:text-blue-700">查看路线 <i class="fa fa-angle-right ml-1 transition-transform group-hover:translate-x-1"></i></span>
                </div>
            </div>
        </div>
    </section>

    <section id="experiences" class="py-24 bg-gray-50">
        <div class="max-w-7xl mx-auto px-4 md:px-8">
            <div class="flex flex-col lg:flex-row items-center gap-16">
                <div class="lg:w-1/2">
                    <div class="relative">
                        <img src="https://images.unsplash.com/photo-1505852903341-fc8d3db10436?q=80&w=1000&auto=format&fit=crop" alt="夏威夷体验" class="rounded-[2.5rem] shadow-2xl relative z-10">
                        <div class="absolute inset-0 bg-blue-600 rounded-[2.5rem] transform translate-x-4 translate-y-4 -z-10 opacity-20"></div>
                    </div>
                </div>
                <div class="lg:w-1/2">
                    <span class="text-blue-600 font-bold tracking-wider uppercase text-sm mb-2 block">Experiences</span>
                    <h2 class="text-3xl md:text-4xl font-extrabold text-gray-900 mb-6">不可错过的夏威夷体验</h2>
                    <p class="text-gray-500 mb-10 text-lg leading-relaxed">除了明媚的阳光与柔软的沙滩，夏威夷还有更多深度的波利尼西亚文化与刺激的自然探险等待着您。我们为您精选最高品质的本地游玩项目。</p>
                    <div class="space-y-8">
                        <div class="flex items-start">
                            <div class="flex-shrink-0 w-14 h-14 bg-white text-blue-600 rounded-2xl flex items-center justify-center text-2xl shadow-sm border border-gray-100">
                                <i class="fa fa-helicopter"></i>
                            </div>
                            <div class="ml-6">
                                <h4 class="text-xl font-bold text-gray-900 mb-2">直升机俯瞰隐秘海岸</h4>
                                <p class="text-gray-500 leading-relaxed">飞越考爱岛的纳帕利海岸，以上帝视角欣赏徒步无法到达的壮丽悬崖、深谷与飞瀑。</p>
                            </div>
                        </div>
                        <div class="flex items-start">
                            <div class="flex-shrink-0 w-14 h-14 bg-white text-blue-600 rounded-2xl flex items-center justify-center text-2xl shadow-sm border border-gray-100">
                                <i class="fa fa-ship"></i>
                            </div>
                            <div class="ml-6">
                                <h4 class="text-xl font-bold text-gray-900 mb-2">冬季豪华双体船观鲸</h4>
                                <p class="text-gray-500 leading-relaxed">每年冬季，数以千计的座头鲸洄游至茂宜岛海域。乘坐平稳的双体船，近距离感受海洋巨兽的震撼。</p>
                            </div>
                        </div>
                        <div class="flex items-start">
                            <div class="flex-shrink-0 w-14 h-14 bg-white text-blue-600 rounded-2xl flex items-center justify-center text-2xl shadow-sm border border-gray-100">
                                <i class="fa fa-fire"></i>
                            </div>
                            <div class="ml-6">
                                <h4 class="text-xl font-bold text-gray-900 mb-2">传统卢奥 (Luau) 盛宴</h4>
                                <p class="text-gray-500 leading-relaxed">在星空下品尝地下烤炉烹制的卡鲁亚烤猪，欣赏震撼的萨摩亚火刀舞与优雅的夏威夷草裙舞。</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <section id="contact" class="py-24 bg-white">
        <div class="max-w-4xl mx-auto px-4 text-center">
            <span class="text-blue-600 font-bold tracking-wider uppercase text-sm mb-2 block">Contact Us</span>
            <h2 class="text-3xl md:text-5xl font-extrabold text-gray-900 mb-6">准备好开启夏威夷假日了吗？</h2>
            <p class="text-xl text-gray-500 mb-10 max-w-2xl mx-auto leading-relaxed">告诉我们您的出行计划，我们的旅行专家将在 24 小时内为您提供一对一定制行程方案与报价。</p>
            <div class="flex flex-col sm:flex-row justify-center gap-4">
                <a href="#" class="bg-gray-900 hover:bg-black text-white px-8 py-4 rounded-full font-medium text-lg transition duration-300 shadow-[0_8px_20px_rgba(0,0,0,0.2)] hover:shadow-[0_8px_20px_rgba(0,0,0,0.3)]"><i class="fa fa-wechat mr-2"></i> 添加专属行程顾问</a>
                <a href="#" class="bg-blue-50 text-blue-700 hover:bg-blue-100 px-8 py-4 rounded-full font-medium text-lg transition duration-300 border border-blue-200"><i class="fa fa-phone mr-2"></i> 预约电话回访</a>
            </div>
        </div>
    </section>

    <footer class="bg-gray-900 text-gray-400 py-12 border-t border-gray-800">
        <div class="max-w-7xl mx-auto px-4 text-center">
            <div class="text-2xl font-bold text-white mb-4 flex items-center justify-center gap-2">
                <i class="fa fa-leaf"></i> ${brand}
            </div>
            <p class="mb-6">为您打造纯正、奢华、深度的波利尼西亚风情之旅。</p>
            <div class="flex justify-center space-x-6 mb-8 text-xl">
                <a href="#" class="hover:text-white transition"><i class="fa fa-weibo"></i></a>
                <a href="#" class="hover:text-white transition"><i class="fa fa-wechat"></i></a>
                <a href="#" class="hover:text-white transition"><i class="fa fa-instagram"></i></a>
            </div>
            <p class="text-sm text-gray-500">&copy; ${new Date().getFullYear()} ${brand}. All rights reserved. Hawaiian Travel Expert.</p>
        </div>
    </footer>
  </div>
  `, `
  html { scroll-behavior: smooth; }
  body { -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
  `);
}