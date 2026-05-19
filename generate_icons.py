#!/usr/bin/env python3
"""
generate_icons.py
Génère les icônes SVG de l'extension et les convertit en PNG.
Utilise uniquement la stdlib + cairosvg si disponible, sinon crée
des PNG minimaux via Pillow.
"""

import os, struct, zlib, base64

ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="28" fill="#0d1117"/>
  <circle cx="64" cy="64" r="38" fill="none" stroke="#58a6ff" stroke-width="6" stroke-dasharray="12 4" opacity="0.4"/>
  <circle cx="64" cy="64" r="26" fill="none" stroke="#58a6ff" stroke-width="5"/>
  <circle cx="64" cy="64" r="12" fill="#58a6ff"/>
  <circle cx="64" cy="64" r="5"  fill="#0d1117"/>
  <line x1="64" y1="22" x2="64" y2="32" stroke="#58a6ff" stroke-width="3" stroke-linecap="round"/>
  <line x1="64" y1="96" x2="64" y2="106" stroke="#58a6ff" stroke-width="3" stroke-linecap="round"/>
  <line x1="22" y1="64" x2="32" y2="64" stroke="#58a6ff" stroke-width="3" stroke-linecap="round"/>
  <line x1="96" y1="64" x2="106" y2="64" stroke="#58a6ff" stroke-width="3" stroke-linecap="round"/>
</svg>"""

def make_png(size, svg_str):
    """Crée un PNG simple (carré coloré avec cercle) sans dépendances."""
    # Tentative avec cairosvg
    try:
        import cairosvg
        return cairosvg.svg2png(bytestring=svg_str.encode(), output_width=size, output_height=size)
    except ImportError:
        pass

    # Tentative avec Pillow
    try:
        from PIL import Image, ImageDraw
        img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        r    = size // 2
        # Fond arrondi
        draw.rounded_rectangle([0, 0, size-1, size-1], radius=size//5, fill=(13, 17, 23, 255))
        # Cercle extérieur
        m = size // 8
        draw.ellipse([m, m, size-m-1, size-m-1], outline=(88, 166, 255, 200), width=max(2, size//20))
        # Point central
        c = size // 2
        pr = size // 8
        draw.ellipse([c-pr, c-pr, c+pr, c+pr], fill=(88, 166, 255, 255))
        dot = size // 20
        draw.ellipse([c-dot, c-dot, c+dot, c+dot], fill=(13, 17, 23, 255))

        import io
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return buf.getvalue()
    except ImportError:
        pass

    # Fallback : PNG 1×1 transparent upscalé (minimaliste mais valide)
    def make_minimal_png(w, h):
        def chunk(name, data):
            c = struct.pack(">I", len(data)) + name + data
            return c + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
        
        raw = b""
        for y in range(h):
            raw += b"\x00"  # filter type
            for x in range(w):
                # RGBA pixel : bleu Anthropic
                in_circle = ((x - w//2)**2 + (y - h//2)**2) < (min(w,h)//3)**2
                r, g, b, a = (88, 166, 255, 255) if in_circle else (13, 17, 23, 255)
                raw += bytes([r, g, b, a])
        
        compressed = zlib.compress(raw)
        png  = b"\x89PNG\r\n\x1a\n"
        png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        png += chunk(b"IDAT", compressed)
        png += chunk(b"IEND", b"")
        return png
    
    return make_minimal_png(size, size)


def main():
    icons_dir = os.path.join(os.path.dirname(__file__), "icons")
    os.makedirs(icons_dir, exist_ok=True)

    for size in [16, 48, 128]:
        path = os.path.join(icons_dir, f"icon{size}.png")
        data = make_png(size, ICON_SVG)
        with open(path, "wb") as f:
            f.write(data)
        print(f"✅ Généré : {path} ({len(data)} bytes)")

if __name__ == "__main__":
    main()
