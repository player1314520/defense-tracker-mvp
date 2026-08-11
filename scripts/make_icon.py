"""生成应用图标 app_icon.ico"""
import struct, zlib, os

# 32x32 像素的深蓝色盾牌图标（RGBA）
def make_shield_ico():
    size = 32
    # 创建像素数据：深蓝背景 + 简单盾形
    pixels = []
    cx, cy = size // 2, size // 2
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            # 盾形：上半部分椭圆 + 下半部分尖角
            in_shield = False
            if dy <= 4:  # 上半部分（圆弧）
                if dx*dx + (dy-4)*(dy-4) <= (cx-2)**2:
                    in_shield = True
            else:  # 下半部分（三角尖）
                slope = abs(dx) / max(dy - 4, 1)
                if slope < (cx - 2) / (size * 0.6) and abs(dx) < (cx-2) * (1 - (dy-4)/(size*0.6)):
                    in_shield = True

            if in_shield:
                # 盾形内部：深蓝色主体
                if dy < -2 and abs(dx) < cx - 4:
                    r, g, b, a = 37, 99, 235, 255   # 亮蓝色 top
                else:
                    r, g, b, a = 14, 26, 60, 255    # 深蓝色 body
                # 高光边缘
                if abs(dx) >= cx - 5 or abs(dy + cx) < 3:
                    r, g, b, a = 59, 130, 246, 255  # 边框蓝
            else:
                r, g, b, a = 6, 13, 26, 0  # 透明背景

            pixels.extend([b, g, r, a])  # BGRA

    return bytes(pixels)

def write_ico(path, sizes=(16, 32, 48, 256)):
    """写入 ICO 文件（多分辨率）"""
    images = []
    for sz in sizes:
        pixels = []
        cx = sz // 2
        for y in range(sz):
            for x in range(sz):
                dx, dy = x - cx, y - cx
                scale = sz / 32
                in_shield = False
                threshold = (cx - 2*scale)
                if dy <= 4*scale:
                    if dx*dx + (dy-4*scale)**2 <= threshold**2:
                        in_shield = True
                else:
                    bottom = sz * 0.6
                    frac = (dy - 4*scale) / bottom
                    if frac < 1 and abs(dx) < threshold * (1 - frac):
                        in_shield = True

                if in_shield:
                    b, g, r, a = 14, 26, 60, 255
                    if dy < -2*scale and abs(dx) < threshold * 0.7:
                        b, g, r, a = 235, 99, 37, 255
                    if abs(dx) >= threshold * 0.85:
                        b, g, r, a = 246, 130, 59, 255
                else:
                    b, g, r, a = 26, 13, 6, 0

                pixels.extend([b, g, r, a])

        # PNG 编码（256x256 用 PNG，其他用 BMP）
        if sz == 256:
            import zlib
            raw = b''
            for row in range(sz):
                raw += b'\x00'  # filter type
                raw += bytes(pixels[row*sz*4:(row+1)*sz*4])
            def png_chunk(name, data):
                c = struct.pack('>I', len(data)) + name + data
                return c + struct.pack('>I', zlib.crc32(name + data) & 0xffffffff)
            png = b'\x89PNG\r\n\x1a\n'
            png += png_chunk(b'IHDR', struct.pack('>IIBBBBB', sz, sz, 8, 6, 0, 0, 0))
            png += png_chunk(b'IDAT', zlib.compress(raw, 9))
            png += png_chunk(b'IEND', b'')
            images.append((sz, png, True))
        else:
            # BMP 格式（无文件头，只有 DIB 头）
            bmp_data = struct.pack('<IiiHHIIiiII',
                40, sz, -sz, 1, 32, 0, len(pixels), 0, 0, 0, 0)
            bmp_data += bytes(pixels)
            images.append((sz, bmp_data, False))

    # 写 ICO 文件头
    count = len(images)
    header = struct.pack('<HHH', 0, 1, count)
    offset = 6 + count * 16
    entries = b''
    image_data = b''
    for sz, data, is_png in images:
        w = h = 0 if sz == 256 else sz  # 256 表示为 0
        entries += struct.pack('<BBBBHHII', w, h, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        image_data += data

    with open(path, 'wb') as f:
        f.write(header + entries + image_data)

if __name__ == '__main__':
    # 脚本位于 scripts/ 子目录，切换到项目根目录
    import os as _os
    _os.chdir(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..'))
    try:
        write_ico('app_icon.ico')
        print("[OK] app_icon.ico 生成成功")
    except Exception as e:
        print(f"[WARN] 图标生成失败: {e}")
        # 创建最小有效 ICO（1x1 透明）作为后备
        try:
            minimal = (
                b'\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00'
                b'\x18\x00\x30\x00\x00\x00\x16\x00\x00\x00'
                b'\x28\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00'
                b'\x01\x00\x18\x00\x00\x00\x00\x00\x04\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\xff\xff\xff\x00\x00\x00\x00\x00'
            )
            with open('app_icon.ico', 'wb') as f:
                f.write(minimal)
            print("[OK] 使用后备图标")
        except Exception:
            pass
