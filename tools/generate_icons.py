import os
from PIL import Image, ImageDraw

def draw_sentry_icon(size):
    img = Image.new("RGBA", (size, size), (11, 15, 20, 255))
    draw = ImageDraw.Draw(img)
    
    scale = size / 512.0
    
    def pt(x, y):
        return (int(x * scale), int(y * scale))
    
    # Outer shield
    outer_poly = [
        pt(256, 64),
        pt(400, 128),
        pt(380, 270),
        pt(256, 424),
        pt(132, 270),
        pt(112, 128),
    ]
    draw.polygon(outer_poly, fill=(16, 22, 30, 255), outline=(41, 51, 66, 255), width=max(1, int(10 * scale)))
    
    # Inner shield
    inner_poly = [
        pt(256, 110),
        pt(360, 155),
        pt(345, 260),
        pt(256, 380),
        pt(167, 260),
        pt(152, 155),
    ]
    draw.polygon(inner_poly, fill=(21, 29, 39, 255), outline=(76, 141, 255, 255), width=max(1, int(6 * scale)))
    
    # Network interconnect lines
    p_top = pt(256, 180)
    p_left = pt(200, 240)
    p_right = pt(312, 240)
    p_bottom = pt(256, 300)
    
    line_w = max(1, int(4 * scale))
    draw.line([p_top, p_left], fill=(41, 51, 66, 255), width=line_w)
    draw.line([p_top, p_right], fill=(41, 51, 66, 255), width=line_w)
    draw.line([p_left, p_bottom], fill=(69, 198, 216, 255), width=line_w)
    draw.line([p_right, p_bottom], fill=(69, 198, 216, 255), width=line_w)
    draw.line([p_left, p_right], fill=(76, 141, 255, 255), width=max(1, int(2 * scale)))
    
    # Nodes
    r_node = max(2, int(12 * scale))
    for p, color in [(p_top, (76, 141, 255)), (p_left, (69, 198, 216)), (p_right, (69, 198, 216)), (p_bottom, (76, 141, 255))]:
        draw.ellipse([p[0] - r_node, p[1] - r_node, p[0] + r_node, p[1] + r_node], fill=(21, 29, 39, 255), outline=color, width=max(1, int(3 * scale)))
        r_inner = max(1, int(4 * scale))
        draw.ellipse([p[0] - r_inner, p[1] - r_inner, p[0] + r_inner, p[1] + r_inner], fill=color)
        
    # Central sentry diamond
    p_c1 = pt(256, 222)
    p_c2 = pt(272, 240)
    p_c3 = pt(256, 258)
    p_c4 = pt(240, 240)
    draw.polygon([p_c1, p_c2, p_c3, p_c4], fill=(53, 201, 138, 255), outline=(243, 246, 250, 255), width=max(1, int(2 * scale)))
    
    return img

os.makedirs("src-tauri/icons", exist_ok=True)

img_32 = draw_sentry_icon(32)
img_32.save("src-tauri/icons/32x32.png")

img_128 = draw_sentry_icon(128)
img_128.save("src-tauri/icons/128x128.png")

img_256 = draw_sentry_icon(256)
img_256.save("src-tauri/icons/128x128@2x.png")

img_512 = draw_sentry_icon(512)
img_512.save("src-tauri/icons/icon.png")

# Save multi-resolution Windows ICO
img_512.save("src-tauri/icons/icon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("Icons generated successfully!")
