function out = progressivekey(text,key,direction,varargin)
% PROGRESSIVE KEY Cipher encoder/decoder
% ACA Progressive Key (two-stage Vigenère with group-wise progressive key).
%
% The plaintext is arranged in consecutive groups whose length equals the
% period (length of the keyword). First, an ordinary periodic Vigenère
% encipherment using the keyword produces a "primary" ciphertext.
% Then, a second Vigenère encipherment is applied group by group, using
% a single-letter key that progresses along the alphabet.
%
% With progression index = 1 (default), the group keys for the second
% encipherment are:
%   Group 1 -> 'A', Group 2 -> 'B', Group 3 -> 'C', ...
% With progression index = p, they become:
%   Group 1 -> 'A', Group 2 -> 'A'+p, Group 3 -> 'A'+2p (mod 26), ...
%
% This function implements both encryption and decryption:
%   1) Encryption:
%        - Primary ciphertext C1 = Vigenère(plaintext, keyword).
%        - Final ciphertext C2 obtained by Caesar/Vigenère on each
%          length(period) block of C1 with the appropriate progressive
%          single-letter key.
%   2) Decryption:
%        - Undo the progressive group Caesar/Vigenère on C2 to recover C1.
%        - Decrypt C1 with the keyword by standard Vigenère.
%
% Only letters A–Z are processed; all other characters are removed before
% encipherment/decipherment.
%
% Syntax:
%   out = progressivekey(text,key,direction)
%   out = progressivekey(text,key,direction,progindex)
%
% Input:
%   text      - Character array to encode or decode.
%   key       - Keyword used as Vigenère key (period = length(key)).
%   direction - 1 to encrypt, -1 to decrypt.
%   progindex - (optional) progression index (integer 1–25, default 1).
%
% Output (struct):
%   out.plain      - Plaintext (A–Z only, uppercase).
%   out.key        - Used keyword (A–Z only, uppercase).
%   out.progindex  - Used progression index.
%   out.encrypted  - Ciphertext (A–Z only, uppercase).
%
% Example (structure of use):
% out = progressivekey('Hide the gold into the tree stump','LEPRECHAUN',1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRECHAUN'
%     progindex: 1
%     encrypted: 'SMSVXJLGIYPNDLTWPFOFRKJMAQY'
% 
% out = progressivekey('SMSVXJLGIYPNDLTWPFOFRKJMAQY','LEPRECHAUN',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'SMSVXJLGIYPNDLTWPFOFRKJMAQY'
%           key: 'LEPRECHAUN'
%     progindex: 1
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% ------------------------ Input parsing & validation ------------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key', @(x) ischar(x));
addRequired(p,'direction',@(x) ...
    validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'progindex',1,@(x) ...
    validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','>=',1,'<=',25}));
parse(p,text,key,direction,varargin{:});
progindex = p.Results.progindex;
clear p

% ------------------------ Preprocessing ------------------------
% Uppercase and keep only A–Z
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];

ckey = double(upper(key));
ckey(ckey < 65 | ckey > 90) = [];

% Basic checks
assert(~isempty(ckey),'Key must contain at least one alphabetic character (A–Z).');

switch direction
    case 1 % encrypt
        out.plain = char(ctext);
    case -1 % decrypt
        out.encrypted = char(ctext);
end

out.key = char(ckey);
out.progindex = progindex;

% Nothing to do if text is empty after cleaning
LT = length(ctext);
if LT == 0
    switch direction
        case 1
            out.encrypted = '';
        case -1
            out.plain = '';
    end
    return
end

period = length(ckey);

% ------------------------ Core logic ------------------------
switch direction
    case 1  % ---------------------- Encryption -----------------------------
        % 1) Primary Vigenère encryption with the keyword
        vout = vigenere(char(ctext),char(ckey),1);
        C1 = double(vout.encrypted); % primary ciphertext as ASCII codes
        
        % 2) Second pass: group-wise progressive single-letter key
        C2 = zeros(1,LT);
        nGroups = ceil(LT / period);
        
        for g = 0:nGroups-1
            idxStart = g*period + 1;
            idxEnd   = min((g+1)*period,LT);
            
            % progression key shift: A=0, B=1, ... (mod 26)
            shift = mod(g * progindex,26);
            
            block = C1(idxStart:idxEnd) - 65;           % 0..25
            block = mod(block + shift,26) + 65;         % apply Caesar(+)
            C2(idxStart:idxEnd) = block;
        end
        
        out.encrypted = char(C2);
        
    case -1 % ---------------------- Decryption -----------------------------
        % 1) Undo the progressive second pass first (recover primary C1)
        C2 = ctext;            % ciphertext as ASCII codes
        C1 = zeros(1,LT);
        nGroups = ceil(LT / period);
        
        for g = 0:nGroups-1
            idxStart = g*period + 1;
            idxEnd   = min((g+1)*period,LT);
            
            % same progression key shift
            shift = mod(g * progindex,26);
            
            block = C2(idxStart:idxEnd) - 65;          % 0..25
            block = mod(block - shift,26) + 65;        % apply Caesar(−)
            C1(idxStart:idxEnd) = block;
        end
        
        % 2) Now C1 is the primary ciphertext from ordinary Vigenère.
        %    Decrypt it with the keyword.
        vout = vigenere(char(C1),char(ckey),-1);
        out.plain = vout.plain;
end

end
