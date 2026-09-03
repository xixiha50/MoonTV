import { NextResponse } from 'next/server';

import { isAllowedProxyUrl } from '@/lib/url-security';

export const runtime = 'edge';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const imageUrl = searchParams.get('url');

  if (!imageUrl) {
    return NextResponse.json({ error: 'Missing image URL' }, { status: 400 });
  }

  // SSRF 防护：只挡内网/保留地址，允许任意外网图床
  // （用 'open' 而非 'image'，避免非豆瓣图床被白名单拒绝导致破图）
  if (!isAllowedProxyUrl(imageUrl, 'open')) {
    return NextResponse.json({ error: 'URL not allowed' }, { status: 403 });
  }

  try {
    const target = new URL(imageUrl);

    // 按域名补 Referer，绕过反盗链
    // 豆瓣 / bgm.tv 有严格 Referer 校验，必须用固定值；
    // 其他图床一律回传自身域名作为 Referer（最常见的绕过方式）
    let referer: string;
    if (target.hostname.includes('bgm.tv')) {
      referer = 'https://bgm.tv/';
    } else if (
      target.hostname.includes('doubanio.com') ||
      target.hostname.includes('douban.com')
    ) {
      referer = 'https://movie.douban.com/';
    } else {
      referer = `${target.protocol}//${target.host}/`;
    }

    const ua =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36';

    const upstream = await fetch(imageUrl, {
      headers: { Referer: referer, 'User-Agent': ua },
    });

    if (!upstream.ok) {
      return NextResponse.json(
        { error: upstream.statusText },
        { status: upstream.status }
      );
    }

    const contentType = upstream.headers.get('content-type');
    if (!upstream.body) {
      return NextResponse.json({ error: 'No body' }, { status: 500 });
    }

    const headers = new Headers();
    if (contentType) headers.set('Content-Type', contentType);
    // 半年 CDN 缓存
    headers.set('Cache-Control', 'public, max-age=15720000, s-maxage=15720000');
    headers.set('CDN-Cache-Control', 'public, s-maxage=15720000');
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Timing-Allow-Origin', '*');

    return new Response(upstream.body, { status: 200, headers });
  } catch (error) {
    return NextResponse.json(
      { error: 'Error fetching image' },
      { status: 500 }
    );
  }
}
