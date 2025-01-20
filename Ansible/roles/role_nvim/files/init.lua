vim = vim
local Plug = vim.fn['plug#']


local success, result = pcall(function()
    vim.call('plug#begin')

    Plug('neovim/nvim-lspconfig')
    Plug('junegunn/vim-easy-align')
    Plug('tomtom/tcomment_vim')
    Plug('nvim-lua/plenary.nvim')
    Plug('nvim-telescope/telescope.nvim', {['branch'] = '0.1.x'})
    Plug('neoclide/coc.nvim', {['branch'] = 'release'})

    vim.call('plug#end')
end)
if not success then
    print("Error encountered: " .. result)
    os.execute('sh -c \'curl -fLo "${XDG_DATA_HOME:-$HOME/.local/share}"/nvim/site/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim\'')

    vim.call('plug#begin')

    Plug('neovim/nvim-lspconfig')
    Plug('junegunn/vim-easy-align')
    Plug('tomtom/tcomment_vim')
    Plug('nvim-lua/plenary.nvim')
    Plug('nvim-telescope/telesope.nvim', {['tag'] = '0.1.8'})
    Plug('neoclide/coc.nvim', {['branch'] = 'release'})

    vim.call('plug#end')
end

-- Setup language servers.
local lspconfig = require('lspconfig')
lspconfig.pyright.setup {}

-- Global mappings.
-- See `:help vim.diagnostic.*` for documentation on any of the below functions
vim.keymap.set('n', '<space>e', vim.diagnostic.open_float)
vim.keymap.set('n', '[d', vim.diagnostic.goto_prev)
vim.keymap.set('n', ']d', vim.diagnostic.goto_next)
vim.keymap.set('n', '<space>q', vim.diagnostic.setloclist)

-- Use LspAttach autocommand to only map the following keys
-- after the language server attaches to the current buffer
vim.api.nvim_create_autocmd('LspAttach', {
  group = vim.api.nvim_create_augroup('UserLspConfig', {}),
  callback = function(ev)
    -- Enable completion triggered by <c-x><c-o>
    vim.bo[ev.buf].omnifunc = 'v:lua.vim.lsp.omnifunc'

    -- Buffer local mappings.
    -- See `:help vim.lsp.*` for documentation on any of the below functions
    local opts = { buffer = ev.buf }
    vim.keymap.set('n', 'gD', vim.lsp.buf.declaration, opts)
    vim.keymap.set('n', 'gd', vim.lsp.buf.definition, opts)
    vim.keymap.set('n', 'K', vim.lsp.buf.hover, opts)
    vim.keymap.set('n', 'gi', vim.lsp.buf.implementation, opts)
    vim.keymap.set('n', '<C-k>', vim.lsp.buf.signature_help, opts)
    vim.keymap.set('n', '<space>wa', vim.lsp.buf.add_workspace_folder, opts)
    vim.keymap.set('n', '<space>wr', vim.lsp.buf.remove_workspace_folder, opts)
    vim.keymap.set('n', '<space>wl', function()
	    print(vim.inspect(vim.lsp.buf.list_workspace_folders()))
	end, opts)
    vim.keymap.set('n', '<space>D', vim.lsp.buf.type_definition, opts)
    vim.keymap.set('n', '<space>rn', vim.lsp.buf.rename, opts)
    vim.keymap.set({ 'n', 'v' }, '<space>ca', vim.lsp.buf.code_action, opts)
    vim.keymap.set('n', 'gr', vim.lsp.buf.references, opts)
    vim.keymap.set('n', '<space>f', function()
      vim.lsp.buf.format { async = true }
    end, opts)
  end,
})

function toggle_line_numbers()
    local current = vim.wo.number
    if current then 
        vim.wo.number         = false
        vim.wo.relativenumber = false
    else
        vim.wo.number         = true
        vim.wo.relativenumber = true
    end
end

function quad_terminal()
    vim.cmd('vsplit')
    vim.cmd('split')

    vim.cmd('wincmd l')
    vim.cmd('split')

    vim.cmd('wincmd h')
    vim.cmd('term')
    vim.cmd('wincmd l')
    vim.cmd('term')
    vim.cmd('wincmd j')
    vim.cmd('term')
    vim.cmd('wincmd h')
    vim.cmd('term')
    vim.cmd('wincmd k')
end

function winCMD(letter)
    local command = string.format('wincmd %s', letter)
    vim.cmd(command)
end

vim.opt.termguicolors = true
vim.cmd 'colorscheme industry'
vim.cmd("highlight Visual guibg=#00FF00 guifg=#000000 gui=BOLD")
vim.cmd("highlight Cursor guifg=#000000 guibg=#00ff00 gui=BOLD")
vim.cmd("highlight TermCursor guifg=#000000 guibg=#00ff00 gui=BOLD")
vim.cmd("highlight TermCursorNC guifg=#000000 guibg=#00ff00 gui=BOLD")
vim.cmd("highlight CursorLine guibg=#232323 gui=NONE")
vim.cmd("highlight CursorLineNr guifg=#00FF00 gui=BOLD")
vim.cmd("highlight StatusLine guibg=#00FF00 guifg=#000000 gui=BOLD")
vim.cmd("highlight StatusLineTerm guibg=#00FF00 guifg=#000000 gui=BOLD")
vim.cmd("highlight MsgArea guifg=#00FF00 guibg=#000000 gui=BOLD")
vim.cmd("highlight LineNr guifg=#00FF00 gui=NONE")

vim.opt.breakindent = true
vim.opt.expandtab = true
vim.opt.tabstop = 4
vim.opt.shiftwidth = 4
vim.opt.autoindent = true
vim.opt.cursorline = true

-- Terminal Keybinds
vim.keymap.set('t', '<A-x>', '<C-Bslash><C-N>', {noremap = true, silent = false})
vim.keymap.set('t', '<A-h>', '<Cmd>wincmd h<CR>', {noremap = true, silent = false})
vim.keymap.set('t', '<A-j>', '<Cmd>wincmd j<CR>', {noremap = true, silent = false})
vim.keymap.set('t', '<A-k>', '<Cmd>wincmd k<CR>', {noremap = true, silent = false})
vim.keymap.set('t', '<A-l>', '<Cmd>wincmd l<CR>', {noremap = true, silent = false})

-- Visual Bind
-- Vis+Sel
vim.keymap.set('v', '<A-y>', '"+y', {noremap = true, silent = true})
-- Vis Only
vim.keymap.set('x', 'ga', '<Plug>(EasyAlign', {})
-- Sel Only

-- Normal Binds
vim.keymap.set('n', '<leader>n', ':lua toggle_line_numbers()<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<leader>ot', ':lua quad_terminal()<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<leader>nt', ':tabnew<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<leader>tc', ':tabc<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<leader>tn', ':tabn<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<leader>tp', ':tabp<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<leader>be', ':bro e .<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<leader>bw', ':bro w .<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<A-q>', ':qa!<CR>', {noremap = true, silent = true})
vim.keymap.set('n', '<A-h>', '<Cmd>wincmd h<CR>', {noremap = true, silent = false})
vim.keymap.set('n', '<A-j>', '<Cmd>wincmd j<CR>', {noremap = true, silent = false})
vim.keymap.set('n', '<A-k>', '<Cmd>wincmd k<CR>', {noremap = true, silent = false})
vim.keymap.set('n', '<A-l>', '<Cmd>wincmd l<CR>', {noremap = true, silent = false})
local telescope = require('telescope.builtin')
vim.keymap.set('n', '<leader>ff', telescope.find_files, {})
vim.keymap.set('n', '<leader>fg', telescope.live_grep, {})
vim.keymap.set('n', '<leader>fb', telescope.buffers, {})
vim.keymap.set('n', '<leader>fh', telescope.help_tags, {})
