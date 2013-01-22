/*
 * (c) 2013, Tim "diff" Strazzere - diff@lookout.com
 *           strazz@gmail.com - http://www.strazzere.com
 *
 * -> You are free to use this code as long as you keep the original copyright <-
 * An IDA plugin to display Dakvik header information
 *
 * Outline, concept and lots of code adapted (i.e. stolen) from fG!'s Mach-O plugin
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * dalvikplugin.h
 *
 */

// IDA SDK includes
#include <ida.hpp> 
#include <idp.hpp> 
#include <loader.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>

// Macro taken directly from fG!'s Mach-O plugin macros header
#define COMMENT_DWORD(addr, msg) \
  doDwrd(addr, 4); set_cmt(addr, msg, 0);

// Structure to keep all information about the our sample view
struct sample_info_t
{
  TForm *form;
  TCustomControl *cv;
  strvec_t sv;
  sample_info_t(TForm *f) : form(f), cv(NULL) {}
};

// Bare-bones structs for dalvik headers
typedef uint32_t u4;

typedef struct {
  char dex[3];
  char newline[1];
  char ver[3];
  char zero[1];
} dex_magic;

typedef struct {
  dex_magic magic;
  u4 checksum[1];
  unsigned char signature[20];
  u4 file_size[1];
  u4 header_size[1];
  u4 endian_tag[1];
  u4 link_size[1];
  u4 link_off[1];
  u4 map_off[1];
  u4 string_ids_size[1];
  u4 string_ids_off[1];
  u4 type_ids_size[1];
  u4 type_ids_off[1];
  u4 proto_ids_size[1];
  u4 proto_ids_off[1];
  u4 field_ids_size[1];
  u4 field_ids_off[1];
  u4 method_ids_size[1];
  u4 method_ids_off[1];
  u4 class_defs_size[1];
  u4 class_defs_off[1];
  u4 data_size[1];
  u4 data_off[1];
} dex_header;
