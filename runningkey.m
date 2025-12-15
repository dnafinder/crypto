function out = runningkey(text,key,direction)
% RUNNINGKEY Cipher encoder/decoder (Running Key / Book cipher)
% A running key cipher is a polyalphabetic substitution cipher where
% the key is not a short keyword but a long piece of text (a “running”
% key), typically from a book, article, or any sufficiently long passage.
%
% Each plaintext letter is encrypted using a Vigenère-style shift driven
% by the corresponding letter of the running key:
%   - Letters A–Z are mapped to 0–25.
%   - Encryption:  C = (P + K) mod 26
%   - Decryption:  P = (C − K) mod 26
%
% Only letters A–Z are used for the actual transformation:
%   - text  : all non A–Z characters are removed before processing.
%   - key   : all non A–Z characters are removed, then truncated so that
%             its cleaned length matches that of the cleaned text.
%
% The full cleaned key (after removing non A–Z characters) is stored in
% out.key, while the actually used prefix (same length as text) is stored
% in out.keystream.
%
% Syntax:
%   out = runningkey(text,key,direction)
%
% Input:
%   text      - Character array to encode or decode.
%   key       - Character array containing the running key text
%               (must contain at least as many A–Z letters as text).
%   direction - 1 to encrypt, -1 to decrypt.
%
% Output (structure):
%   out.plain     - Plaintext (A–Z only, uppercase).
%   out.key       - Cleaned running key (A–Z only, uppercase).
%   out.keystream - Prefix of the key actually used (same length as text).
%   out.encrypted - Ciphertext (A–Z only, uppercase).
%
% Example:
%
%   out = runningkey('Hide the gold into the tree stump', ...
%                    'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 1)
%
%   out =
%
%     struct with fields:
%
%          plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%            key: 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'
%       keystream: 'THEQUICKBROWNFOXJUMPSOVERTH'
%      encrypted: 'APHUNPGQPCREAYCQQYFGWSNXLFW'
%
%   out = runningkey('APHUNPGQPCREAYCQQYFGWSNXLFW', ...
%                    'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', -1)
%
%   out =
%
%     struct with fields:
%
%      encrypted: 'APHUNPGQPCREAYCQQYFGWSNXLFW'
%            key: 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'
%       keystream: 'THEQUICKBROWNFOXJUMPSOVERTH'
%          plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also vigenere, autokey, beaufort, gronsfeld, keyphrase
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% --- Input parsing -------------------------------------------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key', @(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% --- Cleaning of text and key (A–Z only) --------------------------------
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];

ckey = double(upper(key));
ckey(ckey < 65 | ckey > 90) = [];

assert(~isempty(ctext), ...
    'Text must contain at least one alphabetic character A–Z.');
assert(~isempty(ckey), ...
    'Key must contain at least one alphabetic character A–Z.');

LT = length(ctext);
LK = length(ckey);
assert(LK >= LT, ...
    'Running key must be at least as long as the cleaned text (need at least %d letters).', LT);

% Build the actually used keystream (prefix of the cleaned key)
keystream = ckey(1:LT);

% --- High-level I/O fields ----------------------------------------------
switch direction
    case 1
        out.plain = char(ctext);
    case -1
        out.encrypted = char(ctext);
end
out.key       = char(ckey);
out.keystream = char(keystream);

% --- Core running key operation (Vigenère-style) -------------------------
% Use the same algebraic form as in vigenere.m, but with the running key
fun = @(t,k) char(65 + mod((t - 65) + (k - 65) * direction, 26));

switch direction
    case 1  % Encrypt
        out.encrypted = fun(ctext, keystream);
    case -1 % Decrypt
        out.plain = fun(ctext, keystream);
end
