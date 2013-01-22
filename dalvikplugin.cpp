/*
 * Dalivk-Plugin v0.1
 *
 * (c) 2013, Tim "diff" Strazzere - diff@lookout.com
 *           strazz@gmail.com - http://www.strazzere.com
 * 
 * -> You are free to use this code as long as you keep the original copyright <-
 *
 * An IDA plugin to display Dakvik header information
 *
 * Outline, concept and lots of code adapted (i.e. stolen) from fG!'s Mach-O plugin
 * GUI code based on Custom viewer sample plugin by Ilfak Guilfanov.
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
 * dalivkplugin.cpp
 *
 */

#include "dalvikplugin.h"

#define DEBUG 1

int counter = 0;

int IDAP_init(void)
{
  // f_DALVIK does not exist for filetype, so we need to check against processor id
  if (ph.id != PLFM_DALVIK)
    {
      // if it's not dalvik binary then plugin is unavailable
      msg("[dalvik plugin] Executable format must be parsed by the Dalvik processor!");
      return PLUGIN_SKIP;
    }   
  return PLUGIN_KEEP;
}

void IDAP_term(void) 
{
    return;
}

// TODO: Need to use QT since apparently native windows will be deprecated "next version",
//       or atleast that is what IDA Pro v6.4 says
void IDAP_run(int arg)
{
  // Workaround to the form problems - to be removed when fixed
  char mycaption[17];
  qsnprintf(mycaption, 17, "Dalvik Header %2d", counter);
  counter++;
	
  HWND hwnd = NULL;
  // Try to create the custom view
  TForm *form = create_tform(mycaption, &hwnd);
  // If creation failed, maybe it already exists
  // this doesn't seem to work with the new QT GUI, only with the old one
  if ( hwnd == NULL )
    {
      warning("Could not create custom view window\n"
	      "perhaps it is open?\n"
	      "Switching to it.");
      // Search for the form with this specific caption
      form = find_tform("Dalvik Header");
      // If found then activate it
      if ( form != NULL )
	switchto_tform(form, true);
      return;
    }
  // Allocate block to hold info about our sample view
  sample_info_t *si = new sample_info_t(form);

  // Retrieve the address of the header - though for dex files
  // this should always be at 0, otherwise it's not likely it is a valid file
  segment_t *textSeg = get_segm_by_name("HEADER");
#if DEBUG
  msg("Text segment is at %llx\n", (long long)textSeg->startEA);
#endif

  int dex_header_size = sizeof(dex_header);
  dex_header *dh;
  dh = (dex_header *)qalloc(dex_header_size);

  // Read the dex file's header
  get_many_bytes(textSeg->startEA, dh, dex_header_size);

  // Comment the header
  COMMENT_DWORD(textSeg->startEA, "magic bytes");
  COMMENT_DWORD(textSeg->startEA + 0x8, "checksum");
  COMMENT_DWORD(textSeg->startEA + 0xC, "signature");
  COMMENT_DWORD(textSeg->startEA + 0x20, "file size");
  COMMENT_DWORD(textSeg->startEA + 0x24, "header size");
  COMMENT_DWORD(textSeg->startEA + 0x28, "endianness");
  COMMENT_DWORD(textSeg->startEA + 0x2C, "link section size");
  COMMENT_DWORD(textSeg->startEA + 0x30, "link section offset");
  COMMENT_DWORD(textSeg->startEA + 0x34, "map section offset");
  COMMENT_DWORD(textSeg->startEA + 0x38, "string ids section size");
  COMMENT_DWORD(textSeg->startEA + 0x3C, "string ids section offset");
  COMMENT_DWORD(textSeg->startEA + 0x40, "type ids section size");
  COMMENT_DWORD(textSeg->startEA + 0x44, "type ids section offset");
  COMMENT_DWORD(textSeg->startEA + 0x48, "proto ids section size");
  COMMENT_DWORD(textSeg->startEA + 0x4C, "proto ids section offset");
  COMMENT_DWORD(textSeg->startEA + 0x50, "field ids section size");
  COMMENT_DWORD(textSeg->startEA + 0x54, "field ids section offset");
  COMMENT_DWORD(textSeg->startEA + 0x58, "method ids section size");
  COMMENT_DWORD(textSeg->startEA + 0x5C, "method ids section offset");
  COMMENT_DWORD(textSeg->startEA + 0x60, "class definition section size");
  COMMENT_DWORD(textSeg->startEA + 0x64, "class definition section offset");
  COMMENT_DWORD(textSeg->startEA + 0x68, "data section size");
  COMMENT_DWORD(textSeg->startEA + 0x6C, "data section offset");

  si->sv.push_back(simpleline_t("Nothing out of the ordinary in this dex file"));

  // Prepare data to display
  simpleline_place_t s1;
  simpleline_place_t s2(si->sv.size()-1);

  // Create a custom viewer
  si->cv = create_custom_viewer("", (TWinControl *)form, &s1, &s2, &s1, 0, &si->sv);

  // Finally display the form on the screen
  open_tform(form, FORM_TAB|FORM_MENU|FORM_RESTORE);

  // Clean up
  qfree(dh);
  return;
}

char IDAP_comment[]	= "Plugin to display Dalvik Headers";
char IDAP_help[]	= "Dalvik Plugin";
char IDAP_name[]	= "Display Dalvik Header";
char IDAP_hotkey[]	= "Alt-X";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  IDAP_init,
  IDAP_term,
  IDAP_run,
  IDAP_comment,
  IDAP_help,
  IDAP_name,
  IDAP_hotkey
};
