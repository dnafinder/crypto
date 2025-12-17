function out=vigenere(text,key,direction,varargin)
% VIGENERE Cipher encoder/decoder
% The Vigenère cipher is a method of encrypting alphabetic text by using a
% series of interwoven Caesar ciphers based on the letters of a keyword. It
% is a form of polyalphabetic substitution. Though the cipher is easy to
% understand and implement, for three centuries it resisted all attempts to
% break it; this earned it the description le chiffre indéchiffrable
% (French for 'the indecipherable cipher').
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.
%
% Backward compatible syntax:
%   out = vigenere(text,key,direction)
%
% Extended syntax needed to use QUAGMIRE ENCODER(optional Name-Value pairs):
%   out = vigenere(text,key,direction,'Mode',mode, ...
%                  'PlainAlphabet',plainAlphabet,'CipherAlphabet',cipherAlphabet, ...
%                  'Keystream',keystream,'ShiftStream',shiftStream)
%
% Name-Value pairs:
%   Mode          - 'add' (default) or 'sub'
%                   'add': C = P + K (mod 26), P = C - K (mod 26)
%                   'sub': C = P - K (mod 26), P = C + K (mod 26)
%   PlainAlphabet - 26 unique letters A-Z (default 'A'..'Z')
%   CipherAlphabet- 26 unique letters A-Z (default 'A'..'Z')
%   Keystream     - optional A-Z char vector; mapped as shifts A=0..Z=25
%                   and used as the repeated key stream (overrides KEY repeat)
%   ShiftStream   - optional numeric vector of shifts 0..25 (overrides KEY repeat)
%
% Output:
%   out.plain      - the processed plaintext (A-Z only)
%   out.key        - the used key (A-Z only; legacy behavior preserved)
%   out.encrypted  - the processed ciphertext (A-Z only)
%
% Examples:
%
% out = vigenere('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'SMSVTJLGIYOMCKOVOENEPIHKUOW'
%
% out = vigenere('SMSVTJLGIYOMCKOVOENEPIHKUOW','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'SMSVTJLGIYOMCKOVOENEPIHKUOW'
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also autokey, beaufort, dellaporta, gronsfeld, nihilist, trithemius,
% progressivekey
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub: https://github.com/dnafinder/crypto

% -------------------- Legacy fast-path (bit-for-bit compatible) --------------------
if nargin < 4 || isempty(varargin)

    p = inputParser;
    addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
    addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
    addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
        {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
    parse(p,text,key,direction);
    clear p

    if isstring(text), text = char(text); end
    if isstring(key),  key  = char(key);  end

    % Set all letters in uppercase and convert into ASCII Code.
    ctext = double(upper(text));
    ckey  = double(upper(key));

    % Erase all characters that are not into the range 65 - 90
    ctext(ctext<65 | ctext>90) = [];
    ckey(ckey<65  | ckey>90)  = [];

    assert(~isempty(ckey),'Key must contain at least one alphabetic letter A-Z')

    switch direction
        case 1
            out.plain = char(ctext);
        case -1
            out.encrypted = char(ctext);
    end
    out.key = char(ckey);

    LT = numel(ctext);
    LK = numel(ckey);

    % Handle empty cleaned text gracefully
    if LT == 0
        switch direction
            case 1
                out.encrypted = '';
            case -1
                out.plain = '';
        end
        return
    end

    % Repeat the key to cover all the text
    RL = ceil(LT/LK);
    key_stream = repmat(ckey,1,RL);
    key_stream = key_stream(1:LT);

    % Vigenère in modular arithmetic:
    % En(x) = (x+k) mod 26
    % Dn(x) = (x−k) mod 26
    fun = @(t,k,d) char(65 + mod((t-65) + d.*(k-65), 26));

    switch direction
        case 1 % Encrypt
            out.encrypted = fun(ctext,key_stream,1);
        case -1 % Decrypt
            out.plain = fun(ctext,key_stream,-1);
    end

    return
end

% -------------------- Extended path (optional Name-Value pairs) --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));

addParameter(p,'Mode','add',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addParameter(p,'PlainAlphabet','ABCDEFGHIJKLMNOPQRSTUVWXYZ',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addParameter(p,'CipherAlphabet','ABCDEFGHIJKLMNOPQRSTUVWXYZ',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addParameter(p,'Keystream','',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addParameter(p,'ShiftStream',[],@(x) isnumeric(x) && isvector(x));

parse(p,text,key,direction,varargin{:});
mode = char(lower(string(p.Results.Mode)));
plainAlphabet = char(upper(string(p.Results.PlainAlphabet)));
cipherAlphabet = char(upper(string(p.Results.CipherAlphabet)));
keystream = char(upper(string(p.Results.Keystream)));
shiftStream = p.Results.ShiftStream;
clear p

if isstring(text), text = char(text); end
if isstring(key),  key  = char(key);  end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')
assert(ismember(mode,{'add','sub'}),'Mode must be ''add'' or ''sub''.')

% Clean alphabets
pa = double(plainAlphabet);
ca = double(cipherAlphabet);
pa(pa<65 | pa>90) = [];
ca(ca<65 | ca>90) = [];
assert(numel(pa)==26 && numel(unique(pa))==26,'PlainAlphabet must contain 26 unique letters A-Z.')
assert(numel(ca)==26 && numel(unique(ca))==26,'CipherAlphabet must contain 26 unique letters A-Z.')
plainAlphabet = char(pa);
cipherAlphabet = char(ca);
clear pa ca

% Clean text and key (legacy filtering rules)
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ckey  = double(upper(key));
ckey(ckey<65  | ckey>90)  = [];

% Preserve legacy out.key behavior
out.key = char(ckey);

% Direction-specific in/out fields
switch direction
    case 1
        out.plain = char(ctext);
    case -1
        out.encrypted = char(ctext);
end

LT = numel(ctext);

% Handle empty cleaned text gracefully
if LT == 0
    switch direction
        case 1
            out.encrypted = '';
        case -1
            out.plain = '';
    end
    return
end

% Determine shift stream (0..25) for each text position
if ~isempty(shiftStream)
    validateattributes(shiftStream,{'numeric'},{'real','finite','nonnan','integer','>=',0,'<=',25})
    shiftStream = shiftStream(:).';
    assert(numel(shiftStream)==LT,'ShiftStream length must match filtered text length (%d).',LT)
elseif ~isempty(keystream)
    ks = double(keystream);
    ks(ks<65 | ks>90) = [];
    assert(~isempty(ks),'Keystream must contain at least one letter A-Z.')
    RL = ceil(LT/numel(ks));
    ks = repmat(ks,1,RL);
    ks = ks(1:LT);
    shiftStream = ks - 65;
else
    assert(~isempty(ckey),'Key must contain at least one alphabetic letter A-Z')
    RL = ceil(LT/numel(ckey));
    ks = repmat(ckey,1,RL);
    ks = ks(1:LT);
    shiftStream = ks - 65;
end

% Map text letters to indices in the PlainAlphabet
% Compute output indices
switch mode
    case 'add'
        sEnc = +1;
    case 'sub'
        sEnc = -1;
end

if direction == 1
    % Encrypt: input is plaintext -> map against PlainAlphabet
    [tfIn,inPos] = ismember(char(ctext),plainAlphabet);
    assert(all(tfIn),'Text contains letters not in PlainAlphabet.')
    pIdx = inPos - 1; % 0..25

    cIdx = mod(pIdx + sEnc.*shiftStream, 26);
    out.encrypted = cipherAlphabet(cIdx + 1);

else
    % Decrypt: input is ciphertext -> map against CipherAlphabet
    [tfIn,inPos] = ismember(char(ctext),cipherAlphabet);
    assert(all(tfIn),'Text contains letters not in CipherAlphabet.')
    cIdx = inPos - 1; % 0..25

    pIdx = mod(cIdx - sEnc.*shiftStream, 26);
    out.plain = plainAlphabet(pIdx + 1);
end


end
