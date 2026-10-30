-- cdnca_webp_codec: JPEG/PNG to WebP with libgd. Runs in
-- ngx.run_worker_thread (thread pool cdnca_webp), never in the event loop:
-- it only uses LuaJIT FFI and no ngx.* API. libgd ships with both node
-- runtimes (the image_filter module's dependency) together with libjpeg,
-- libpng and libwebp. libgd reports decode errors through its own error
-- handler and returns NULL (no longjmp out of FFI), so a damaged image
-- yields an error, not a crash.
local ffi = require "ffi"

ffi.cdef [[
typedef struct gdImageStruct gdImage;
gdImage *gdImageCreateFromJpegPtrEx(int size, void *data, int ignore_warning);
gdImage *gdImageCreateFromPngPtr(int size, void *data);
void *gdImageWebpPtrEx(gdImage *im, int *size, int quality);
int gdImagePaletteToTrueColor(gdImage *src);
void gdImageSaveAlpha(gdImage *im, int saveAlphaArg);
void gdImageDestroy(gdImage *im);
void gdFree(void *m);
]]

local _M = {}
local gd

local function library()
    if gd == nil then
        -- the runtimes ship the versioned name only (no -dev symlink)
        local ok, loaded = pcall(ffi.load, "libgd.so.3")
        if not ok then
            ok, loaded = pcall(ffi.load, "gd")
        end
        gd = ok and loaded or false
    end
    return gd
end

-- convert(kind, data, quality): the WebP bytes, or nil and a reason.
-- kind is "jpeg" or "png" (sniffed by the caller).
function _M.convert(kind, data, quality)
    local lib = library()
    if not lib then
        return nil, "libgd unavailable"
    end
    local size = #data
    local buffer = ffi.cast("void *", data)
    local image
    if kind == "jpeg" then
        image = lib.gdImageCreateFromJpegPtrEx(size, buffer, 1)
    elseif kind == "png" then
        image = lib.gdImageCreateFromPngPtr(size, buffer)
    else
        return nil, "unsupported image"
    end
    if image == nil then
        return nil, "decode failed"
    end
    image = ffi.gc(image, lib.gdImageDestroy)
    if kind == "png" then
        -- a palette PNG is encoded through true colour, transparency kept
        lib.gdImagePaletteToTrueColor(image)
        lib.gdImageSaveAlpha(image, 1)
    end
    local length = ffi.new("int[1]")
    local out = lib.gdImageWebpPtrEx(image, length, quality)
    lib.gdImageDestroy(ffi.gc(image, nil))
    if out == nil or length[0] <= 0 then
        if out ~= nil then lib.gdFree(out) end
        return nil, "encode failed"
    end
    local webp = ffi.string(out, length[0])
    lib.gdFree(out)
    return webp
end

return _M
