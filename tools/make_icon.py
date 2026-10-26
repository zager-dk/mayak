"""Рисует иконку «Маяк VPN» (маяк с лучом на ночном фоне) → Assets/mayak.png и mayak.ico."""
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

S = 1024  # рисуем крупно, потом уменьшаем
out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "src" / "MayakVPN" / "Assets"
out_dir.mkdir(parents=True, exist_ok=True)

NAVY = (14, 26, 43, 255)
NAVY2 = (31, 52, 82, 255)
AMBER = (245, 165, 36, 255)
WHITE = (246, 244, 238, 255)
RED = (214, 69, 69, 255)

img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

# Фон: скруглённый квадрат с вертикальным градиентом
bg = Image.new("RGBA", (S, S))
bd = ImageDraw.Draw(bg)
for y in range(S):
    t = y / S
    c = tuple(int(NAVY2[i] * (1 - t) + NAVY[i] * t) for i in range(3)) + (255,)
    bd.line([(0, y), (S, y)], fill=c)
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=220, fill=255)
img.paste(bg, (0, 0), mask)

# Лучи света
beam = Image.new("RGBA", (S, S), (0, 0, 0, 0))
b = ImageDraw.Draw(beam)
lamp = (512, 330)
b.polygon([lamp, (S + 80, 150), (S + 80, 470)], fill=(245, 165, 36, 120))
b.polygon([lamp, (-80, 150), (-80, 470)], fill=(245, 165, 36, 120))
beam = beam.filter(ImageFilter.GaussianBlur(14))
beam_masked = Image.new("RGBA", (S, S), (0, 0, 0, 0))
beam_masked.paste(beam, (0, 0), mask)
img = Image.alpha_composite(img, beam_masked)

d = ImageDraw.Draw(img)

# Море
d.rounded_rectangle([0, 820, S - 1, S - 1], radius=0, fill=None)
wave = Image.new("RGBA", (S, S), (0, 0, 0, 0))
wd = ImageDraw.Draw(wave)
wd.rectangle([0, 840, S, S], fill=(9, 18, 31, 255))
for i, y in enumerate([860, 910]):
    for x in range(-60, S + 60, 120):
        wd.arc([x, y - 20, x + 120, y + 20], 200, 340, fill=(60, 90, 130, 255), width=10)
wave_masked = Image.new("RGBA", (S, S), (0, 0, 0, 0))
wave_masked.paste(wave, (0, 0), mask)
img = Image.alpha_composite(img, wave_masked)
d = ImageDraw.Draw(img)

# Башня: трапеция с полосами
top_y, base_y = 400, 850
top_half, base_half = 85, 150
d.polygon([(512 - top_half, top_y), (512 + top_half, top_y), (512 + base_half, base_y), (512 - base_half, base_y)], fill=WHITE)
for y0, y1 in [(470, 540), (620, 690)]:
    def x_at(y):
        t = (y - top_y) / (base_y - top_y)
        return top_half + (base_half - top_half) * t
    d.polygon([(512 - x_at(y0), y0), (512 + x_at(y0), y0), (512 + x_at(y1), y1), (512 - x_at(y1), y1)], fill=RED)

# Галерея и фонарь
d.rectangle([512 - 120, 375, 512 + 120, 405], fill=WHITE)
d.rectangle([512 - 70, 270, 512 + 70, 375], fill=NAVY)
d.rectangle([512 - 55, 285, 512 + 55, 375], fill=AMBER)
d.polygon([(512 - 95, 270), (512 + 95, 270), (512, 190)], fill=WHITE)

# Сияние фонаря
glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(glow).ellipse([512 - 110, 220, 512 + 110, 440], fill=(255, 200, 90, 90))
glow = glow.filter(ImageFilter.GaussianBlur(30))
img = Image.alpha_composite(img, glow)

png = img.resize((256, 256), Image.LANCZOS)
png.save(out_dir / "mayak.png")
img.save(out_dir / "mayak.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("saved to", out_dir)
