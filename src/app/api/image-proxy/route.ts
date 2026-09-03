import { NextResponse } from 'next/server';

import { isAllowedProxyUrl } from '@/lib/url-security';

export const runtime = 'edge';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const imageUrl = searchParams.get('url');

  if (!imageUrl) {
    return NextResponse.json({ error: 'Missing image URL' }, { status: 400 });
  }

  // SSRF 防护：只允许白名单图床域名
  if (!isAllowedProxyUrl(imageUrl, 'image')) {
    return NextResponse.json({ error: 'URL not allowed' }, { status: 403 });
  }

  try {
    // 按域名补 Referer，绕过反盗链
    const referer = imageUrl.includes('bgm.tv')
      ? 'https://bgm.tv/'
      : 'https://movie.douban.com/';

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
