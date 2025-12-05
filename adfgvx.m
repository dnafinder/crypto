function out=adfgvx(text,key,direction,varargin)
% ADFGVX Cipher encoder/decoder
% In cryptography, the ADFGVX cipher was a field cipher used by the German
% Army on the Western Front during World War I. ADFGVX was an extension of
% an earlier cipher called ADFGX. Invented by Lieutenant Fritz Nebel
% (1891–1977) and introduced in March 1918, the cipher was a fractionating
% transposition cipher which combined a modified Polybius square with a
% single columnar transposition.
%
% The cipher is named after the six possible letters used in the ciphertext:
% A, D, F, G, V and X. The letters were chosen deliberately because they are
% very different from one another in the Morse code, reducing the possibility
% of operator error.
%
% In June 1918, an additional letter, V, was added to the cipher. That
% expanded the grid to 6 × 6, allowing 36 characters to be used.
% This version allows the full alphabet and the digits from 0 to 9.
%
% English, 26 letters, alphabet plus digits are used.
% Only letters A-Z and digits 0-9 are processed; other characters are ignored.
%
% Syntax: 	out=adfgvx(text,key,direction,matrix)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the transposition keyword (character array or string scalar)
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%           matrix - a scrambled 6x6 Polybius matrix (char 6x6) using the
%                    standard English alphabet and digits 0-9. If it is empty and
%                    direction is 1, the software will generate it.
%     Output:
%           out - It is a structure
%           out.plain = the plain text (processed)
%           out.key = the used key (processed)
%           out.matrix = the used matrix
%           out.encrypted = the coded text
%
% Examples:
%
% out=adfgvx('Hide the gold into the tree stump','leprachaun',1, ...
%           ['NA1C3H';'8TB2OM';'E5WRPD';'4F6G7I';'9J0KLQ';'SUVXYZ'])
%
% out=adfgvx('FGAFXAVDDDXGAAAXXXDAXFDDDDAAFDFDDVVGDGFGAFFXAXXAVDVDFX', ...
%           'leprachaun',-1, ...
%           ['NA1C3H';'8TB2OM';'E5WRPD';'4F6G7I';'9J0KLQ';'SUVXYZ'])
%
% See also adfgx, bifid, checkerboard1, checkerboard2, foursquares,
% nihilist, playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'matrix',[],@(x) isempty(x) || (ischar(x) && isequal(size(x),[6,6])));
parse(p,text,key,direction,varargin{:});
matrix = p.Results.matrix;
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% Alphabet + digits:
A = [48:1:57 65:1:90];

% --- Matrix handling ---
if isempty(matrix)
    assert(direction==1,'This algorithm cannot decode without a matrix')
    cmatrix = reshape(A(randperm(36)),[6,6]);
    out.matrix = char(cmatrix);
else
    cmatrix = double(upper(matrix));
    assert(all(ismember(cmatrix(:),A)), ...
        'Matrix must use standard English alphabet and numbers from 0 to 9')
    assert(numel(unique(cmatrix(:)))==36, ...
        'Matrix must contain 36 unique symbols (A-Z and 0-9).')
    out.matrix = upper(matrix);
end
clear A

% --- Filter and normalize text and key (A-Z and 0-9 only) ---
ctext = double(upper(text));
ctext(ctext<48 | ctext>90 | (ctext>57 & ctext<65)) = [];

ckey_raw = double(upper(key));
ckey_raw(ckey_raw<48 | ckey_raw>90 | (ckey_raw>57 & ckey_raw<65)) = [];

assert(~isempty(ckey_raw),'Key must contain at least one valid letter or digit.')

out.key = char(ckey_raw);

% Sort letters/digits in the key for columnar transposition
[~,Idx] = sort(ckey_raw);

% ADFGVX coordinate symbols
P = 'ADFGVX';

switch direction
    case 1 % encrypt
        % Store processed plaintext
        out.plain = char(ctext);

        % Fractionation using the 6x6 square
        [~,locb] = ismember(ctext,cmatrix);
        assert(all(locb>0),'Plaintext contains characters not encodable with the given matrix.')

        [I,J] = ind2sub([6,6],locb);

        % Build ADFGVX digraph stream
        out1 = reshape([P(I); P(J)],1,[]);
        clear locb I J

        % Columnar transposition
        L = numel(out1);
        C = numel(ckey_raw);
        R = ceil(L/C);

        % Pad to full rectangle (use 'Z' that never appears in ADFGVX stream)
        padLen = C*R - L;
        if padLen > 0
            tmp = [out1 repmat('Z',1,padLen)];
        else
            tmp = out1;
        end

        tmp = reshape(tmp,C,R)';     % R x C
        tmp = tmp(:,Idx);           % reorder columns by sorted key

        tmp = tmp(:)';              % read off by columns
        tmp(tmp=='Z') = [];         % remove padding

        out.encrypted = tmp;

        clear tmp out1 L C R padLen

    case -1 % decrypt
        % Store filtered encrypted input
        out.encrypted = char(ctext);

        % Validate ADFGVX alphabet
        Pc = double(P);
        assert(all(ismember(ctext,Pc)), ...
            'Ciphertext must contain only letters A, D, F, G, V, X.')

        L = numel(ctext);
        C = numel(ckey_raw);
        R = ceil(L/C);
        N = C*R;

        tmp = zeros(R,C);

        if L < N
            % Determine which columns are shorter due to padding
            paddingStart = C - N + L + 1;
            tmp(R,paddingStart:C) = 90; % mark padded cells with 'Z'/90

            cwork = ctext;

            for iCol = 1:C
                colPos = Idx(iCol);
                if colPos < paddingStart
                    tmp(:,colPos) = cwork(1:R);
                    cwork(1:R) = [];
                else
                    tmp(1:R-1,colPos) = cwork(1:R-1);
                    cwork(1:R-1) = [];
                end
            end
            clear cwork paddingStart iCol colPos
        else
            tmp2 = reshape(ctext,R,C);
            tmp(:,Idx) = tmp2(:,1:C);
            clear tmp2
        end

        % Recover fractionated stream
        tmp = tmp';
        out1 = tmp(:)';
        out1(out1==90) = []; % remove padding markers

        % Convert ADFGVX pairs back to matrix indices
        Rv = out1(1:2:end);
        Cv = out1(2:2:end);

        for k = 1:6
            Rv(Rv==Pc(k)) = k;
            Cv(Cv==Pc(k)) = k;
        end

        ind = sub2ind([6,6],Rv,Cv);
        out.plain = char(cmatrix(ind));

        clear tmp out1 Rv Cv ind k L C R N Pc
end

end
